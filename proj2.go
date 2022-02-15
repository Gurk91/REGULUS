package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~HELPERS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}

	return
}

func AESEnc(key []byte, data []byte) (output []byte) {
	blocksize := userlib.AESBlockSizeBytes
	dataLen := len(data)
	padding := blocksize - dataLen%blocksize
	iv := userlib.RandomBytes(blocksize)
	if padding == 0 {
		padding = blocksize
	}
	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}
	return userlib.SymEnc(key, iv, data)
}

func AESDec(key []byte, data []byte) (output []byte) {
	output = userlib.SymDec(key, data)
	padding := int(output[len(output)-1])
	return output[:len(output)-padding]
}

func RandomUUID() (uid uuid.UUID) {
	var unique bool
	for {
		uid = uuid.New()
		_, unique = userlib.DatastoreGet(uid)
		if !unique {
			return uid
		}
	}
}

func (userdata *User) UpdateUserMaps(username string, password string) (err error) {
	//Pulls the latest version of the User struct from the datastore

	//retrieve User datastore ID
	unameHash := userlib.Hash([]byte(username))
	unameUUID := bytesToUUID(unameHash)

	datastoreKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	//pwdUUID := bytesToUUID(datastoreKey)

	//getting the user
	var success bool
	var retrived []byte
	retrived, success = userlib.DatastoreGet(unameUUID)
	if !success {
		userlib.DebugMsg("User Not Found or Incorrect Password")
		err = errors.New("user Not Found")
		return err
	}

	if len(retrived)-64 <= 0 {
		userlib.DebugMsg("Datastore attack detected!")
		errors.New("datastore attack detected")
		return err
	}

	retHmac := retrived[len(retrived)-64:]
	userStruct := retrived[:len(retrived)-64]
	hmacKey := userlib.Argon2Key([]byte(password), unameHash, 16)
	correctHMAC, _ := userlib.HMACEval(hmacKey, userStruct)

	integrity := userlib.HMACEqual(retHmac, correctHMAC)
	if !integrity {
		userlib.DebugMsg("STOP! Data has been tampered with!")
		errors.New("datastore attack detected")
		return err
	}

	var currUser *User
	user_bytes := AESDec(datastoreKey, userStruct)
	err = json.Unmarshal(user_bytes, &currUser)
	if err != nil {
		return err
	}

	userdata.FileName_UUId = currUser.FileName_UUId
	userdata.FileUUID_priv = currUser.FileUUID_priv
	userdata.FileUUID_hmac = currUser.FileUUID_hmac
	userdata.FileUUID_FilePriv = currUser.FileUUID_FilePriv
	userdata.Shares = currUser.Shares
	userdata.ShareBytes = currUser.ShareBytes

	return

}

func (userdata *User) UpdateUserDatastore(username string, password string) {
	//Sends the latest version of the User struct to the Datastore

	//Prep stuff to set up the User struct
	unameHash := userlib.Hash([]byte(username))
	unameUUID := bytesToUUID(unameHash)

	passwordHash := userlib.Argon2Key([]byte(password), []byte(username), 16)
	//datastoreKey := bytesToUUID(passwordHash)
	// userUUID := bytesToUUID(userlib.Hash([]byte(username)))
	hmacKey := userlib.Argon2Key([]byte(password), unameHash, 16)

	//Marshalling to JSON
	userMarshal, _ := json.Marshal(userdata)
	userAES := AESEnc(passwordHash, userMarshal)     //AES Encryption key is the pwdHash
	ourHmac, _ := userlib.HMACEval(hmacKey, userAES) //HMAC key argon2 with username as pwd and password as salt

	saved_user_struct := append(userAES, ourHmac...)

	userlib.DatastoreSet(unameUUID, saved_user_struct)

}

func addToTree(child string, parent string, tree map[string][]string, owner string) map[string][]string {
	tree[child] = append(tree[child], parent)
	var curr string
	curr = tree[child][0]
	for curr != owner {
		tree[curr] = append(tree[curr], child)
		curr = tree[curr][0]
	}
	tree[curr] = append(tree[curr], child)

	return tree
}

func (userdata *User) GetFileFromShare(filename string) (filePriv []byte, hmacKey []byte, priv []byte, err error) {
	fileID := userdata.FileName_UUId[filename]
	shareID := userdata.Shares[fileID]
	shareRandBytes := userdata.ShareBytes[shareID]

	err = nil

	//getting the Share struct
	got, success := userlib.DatastoreGet(shareID)
	if !success {
		userlib.DebugMsg("Error getting Share struct")
		err = errors.New("error getting share struct")
		return nil, nil, nil, err
	}
	shareHMAC := got[len(got)-64:]
	shareAES := got[:len(got)-64]

	sharePriv := userlib.Argon2Key(shareRandBytes, []byte(shareID.String()), 16)
	shareHmacKey := userlib.Argon2Key([]byte(shareID.String()), shareRandBytes, 16)
	correctHMAC, _ := userlib.HMACEval(shareHmacKey, shareAES)

	verify := userlib.HMACEqual(shareHMAC, correctHMAC)
	if !verify {
		userlib.DebugMsg("STOP! Share has been tampered with!")
		err = errors.New("stop! share has been tampered with")
		return nil, nil, nil, err
	}

	shareBytes := AESDec(sharePriv, shareAES)

	var newShare *Share
	badJson := json.Unmarshal(shareBytes, &newShare)
	if badJson != nil {
		userlib.DebugMsg("Something wrong with Share bytes received")
		err = badJson
		return nil, nil, nil, err
	}

	filePriv = newShare.FilePriv
	hmacKey = newShare.HmacKey
	priv = newShare.Priv

	return filePriv, hmacKey, priv, err
}

func (userdata *User) revokeHelper(targetUsername string, filename string, tokenBytes []byte, tokenUUID uuid.UUID) (err error) {
	//allows for the revocation of multiple people, especially in the case of
	//when the target user has shared with multiple other people.

	//start by getting the Token
	var token *Token
	err = json.Unmarshal(tokenBytes, &token)
	if err != nil {
		err = errors.New("trouble in token town")
		return err
	}
	//set token access to "revoked"
	token.Acc = false //we'll send the token later
	// token.EncBt = userlib.RandomBytes(16)
	//token.ShUID = RandomUUID()

	//here we simply delete the Share struct from the datastore
	shareID := token.ShUID
	userlib.DatastoreDelete(shareID)

	//sending the Token back to datastore
	tokenBack, _ := json.Marshal(token)

	var recipientPubKey userlib.PublicKeyType
	var worked bool
	recipientPubKey, worked = userlib.KeystoreGet(targetUsername + "RS")
	if !worked {
		userlib.DebugMsg("Error retrieving RSA keys for target user")
		err = errors.New("error retrieving rsa keys for target user")
		return err
	}
	encryptedBytes, bad := userlib.PKEEnc(recipientPubKey, tokenBack)
	if bad != nil {
		userlib.DebugMsg("Error in encryption")
		err = errors.New("error in encryption")
		return err
	}
	dsSig, bad2 := userlib.DSSign(userdata.DSPrivateKey, encryptedBytes)
	if bad2 != nil {
		userlib.DebugMsg("Error in signing")
		err = errors.New("error in signing")
		return err
	}

	final_Token_out := append(encryptedBytes, dsSig...)
	userlib.DatastoreSet(tokenUUID, final_Token_out)

	return err

}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~PROJECT CODE BEGINS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~<----------------->~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~<----------------->~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// User is the structure definition for a user record.
type User struct {
	Username          string
	UserUUID          uuid.UUID
	DSPrivateKey      userlib.DSSignKey
	RSPrivateKey      userlib.PKEDecKey
	DatastoreKey      []byte
	PwdHash           []byte
	FileName_UUId     map[string]uuid.UUID
	FileUUID_priv     map[uuid.UUID][]byte
	FileUUID_hmac     map[uuid.UUID][]byte //stores the HMAC key, not the HMAC itself
	FileUUID_FilePriv map[uuid.UUID][]byte
	Shares            map[uuid.UUID]uuid.UUID //fileUID -> ShareUID
	ShareBytes        map[uuid.UUID][]byte    //ShareUID -> The random bytes inside Token used to decrypt Share struct
	password          string
}

type File struct {
	Owner     string
	OwnerUUID uuid.UUID
	Shares    map[string][]string //a mapping of who shared the file with whom
	Filename  string
	FileUUID  uuid.UUID
	Tokens    map[string][]byte //the names of the people and their share Tokens
	AccessIDs map[string]uuid.UUID
	Appends   int //stores the number of appends made
}

type Token struct {
	EncBt []byte    //used to generate the AES and HMAC keys for encrypting the Share struct
	ShUID uuid.UUID //Datastore key for the Share struct
	Acc   bool      //boolean to check if file is revoked or not
}

type Share struct {
	Priv     []byte    //file's private key
	FileUID  uuid.UUID //file's Datastore identifies
	HmacKey  []byte    //file's HMAC key
	FilePriv []byte    //file's File struct private key (HMAC is the same as above)
	TokenID  uuid.UUID //corresponding Token's UUID, which is what it's set to in the datastore
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	_, reuse := userlib.KeystoreGet(username + "RS")
	if reuse {
		userlib.DebugMsg("Username already exists")
		err = errors.New("username already exists")
		return nil, err
	}

	//Prep stuff to set up the User struct
	unameHash := userlib.Hash([]byte(username))
	unameUUID := bytesToUUID(unameHash)

	datastoreKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	//pwdUUID := bytesToUUID(datastoreKey)
	userUUID := bytesToUUID(userlib.Hash([]byte(username)))
	hmacKey := userlib.Argon2Key([]byte(password), unameHash, 16)

	//Getting RSA and DS public/private keys and setting them in the keystore
	rsaPublic, rsaPrivate, _ := userlib.PKEKeyGen()
	dsPrivate, dsPublic, _ := userlib.DSKeyGen()
	userlib.KeystoreSet(username+"RS", rsaPublic)
	userlib.KeystoreSet(username+"DS", dsPublic)

	//Setting up the User struct
	userdata.Username = username
	userdata.UserUUID = userUUID
	userdata.RSPrivateKey = rsaPrivate
	userdata.DSPrivateKey = dsPrivate
	userdata.FileName_UUId = make(map[string]uuid.UUID)
	userdata.FileUUID_priv = make(map[uuid.UUID][]byte)
	userdata.FileUUID_hmac = make(map[uuid.UUID][]byte) //stores the File Struct HMACs
	userdata.FileUUID_FilePriv = make(map[uuid.UUID][]byte)
	userdata.Shares = make(map[uuid.UUID]uuid.UUID)  //fileUID -> ShareUID
	userdata.ShareBytes = make(map[uuid.UUID][]byte) //ShareUID -> The random bytes inside Token used to decrypt Share struct

	userdata.DatastoreKey = datastoreKey //also used for AES encryption
	userdata.PwdHash = hmacKey           //argon2 with username as pwd and password as salt
	userdata.password = password

	//Marshalling to JSON
	userMarshal, _ := json.Marshal(userdata)
	userAES := AESEnc(datastoreKey, userMarshal)     //AES Encryption key is the pwdHash
	ourHmac, _ := userlib.HMACEval(hmacKey, userAES) //HMAC key argon2 with username as pwd and password as salt

	saved_user_struct := append(userAES, ourHmac...)

	userlib.DatastoreSet(unameUUID, saved_user_struct)

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//retrieve User datastore ID
	datastoreKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	// pwdUUID := bytesToUUID(datastoreKey)

	unameHash := userlib.Hash([]byte(username))
	unameUUID := bytesToUUID(unameHash)

	//getting the user
	var success bool
	var retrived []byte
	retrived, success = userlib.DatastoreGet(unameUUID)
	if !success {
		userlib.DebugMsg("User Not Found or Incorrect Password")
		err = errors.New("User Not Found or Incorrect Password")
		return nil, err
	}

	if len(retrived)-64 <= 0 {
		userlib.DebugMsg("Datastore attack detected!")
		err = errors.New("datastore attack detected")
		return nil, err
	}

	retHmac := retrived[len(retrived)-64:]
	userStruct := retrived[:len(retrived)-64]
	hmacKey := userlib.Argon2Key([]byte(password), unameHash, 16)
	correctHMAC, err := userlib.HMACEval(hmacKey, userStruct)
	if err != nil {
		return nil, err
	}

	integrity := userlib.HMACEqual(retHmac, correctHMAC)
	if !integrity {
		userlib.DebugMsg("STOP! Data has been tampered with!")
		err = errors.New("STOP! Data has been tampered with")
		return nil, err
	}
	user_bytes := AESDec(datastoreKey, userStruct)
	err = json.Unmarshal(user_bytes, userdataptr)
	if err != nil {
		return userdataptr, err
	}

	// fmt.Println("file UID map: ", userdataptr.FileName_UUId)

	userdataptr.password = password

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	// Need to first get the latest user state from datastore
	userdata.UpdateUserMaps(userdata.Username, userdata.password)

	var ok bool
	_, ok = userdata.FileName_UUId[filename]

	var shared bool
	_, shared = userdata.FileUUID_FilePriv[userdata.FileName_UUId[filename]]

	var fileID uuid.UUID
	var storageKey uuid.UUID
	var fileStorageKey uuid.UUID
	var privKey []byte
	var hmacKey []byte
	var filePriv []byte

	var final_data_out []byte
	var final_File_out []byte

	if ok && !shared {
		fileID = userdata.FileName_UUId[filename]
		shareID := userdata.Shares[fileID]
		shareRandBytes := userdata.ShareBytes[shareID]

		//getting the Share struct
		got, success := userlib.DatastoreGet(shareID)
		if !success {
			userlib.DebugMsg("Error getting Share struct")
			err = errors.New("error getting share struct")
			return err
		}
		shareHMAC := got[len(got)-64:]
		shareAES := got[:len(got)-64]

		sharePriv := userlib.Argon2Key(shareRandBytes, []byte(shareID.String()), 16)
		shareHmacKey := userlib.Argon2Key([]byte(shareID.String()), shareRandBytes, 16)
		correctHMAC, err := userlib.HMACEval(shareHmacKey, shareAES)
		if err != nil {
			return err
		}

		verify := userlib.HMACEqual(shareHMAC, correctHMAC)
		if !verify {
			userlib.DebugMsg("STOP! Share has been tampered with!")
			err = errors.New("stop! share has been tampered with")
			return err
		}

		shareBytes := AESDec(sharePriv, shareAES)

		var newShare *Share
		badJson := json.Unmarshal(shareBytes, &newShare)
		if badJson != nil {
			userlib.DebugMsg("Something wrong with Share bytes received")
			err = badJson
			return err
		}

		//time to send the file to the datastore
		storageKey = newShare.FileUID

		privKey = newShare.Priv
		hmacKey = newShare.HmacKey
		filePriv = newShare.FilePriv

		dataAES := AESEnc(privKey, data)
		dataHMAC, _ := userlib.HMACEval(hmacKey, dataAES)
		final_data_out = append(dataAES, dataHMAC...)

		userlib.DatastoreSet(storageKey, final_data_out)

	} else if ok {
		storageKey = userdata.FileName_UUId[filename]
		privKey = userdata.FileUUID_priv[storageKey]
		hmacKey = userdata.FileUUID_hmac[storageKey]

		filePriv = userdata.FileUUID_FilePriv[storageKey]

		dataAES := AESEnc(privKey, data)
		dataHMAC, _ := userlib.HMACEval(hmacKey, dataAES)
		final_data_out = append(dataAES, dataHMAC...)

		userlib.DatastoreSet(storageKey, final_data_out)

	} else {
		//WHEN SAVING A NEW FILE!!!
		//Preparing the UID, Private, and HMAC keys
		storageKey = RandomUUID()
		fileStorageKey = bytesToUUID([]byte(storageKey.String() + "meta"))

		//fmt.Println("storage key: ", storageKey)
		//fmt.Println("file storage key: ", fileStorageKey)

		privKey = userlib.Argon2Key(userlib.RandomBytes(16), []byte(filename), 16)
		hmacKey = userlib.Argon2Key(userlib.RandomBytes(16), privKey, 16)
		filePriv = userlib.Argon2Key(userlib.RandomBytes(16), hmacKey, 16)
		var fileStruct *File = new(File)

		//Setting the private, HMAC, and FileEncryption keys in the User and File
		//structs. Made to ensure maximum ease when sharing.
		userdata.FileName_UUId[filename] = storageKey
		userdata.FileUUID_priv[storageKey] = privKey
		userdata.FileUUID_hmac[storageKey] = hmacKey
		userdata.FileUUID_FilePriv[storageKey] = filePriv

		fileStruct.FileUUID = storageKey
		fileStruct.Filename = filename
		fileStruct.Owner = userdata.Username
		fileStruct.OwnerUUID = userdata.UserUUID
		fileStruct.Tokens = make(map[string][]byte)
		fileStruct.AccessIDs = make(map[string]uuid.UUID)
		fileStruct.Shares = make(map[string][]string)
		fileStruct.Appends = 0

		//Marshalling everything into JSON
		FileJSON, _ := json.Marshal(fileStruct)

		//encryption to AES
		dataAES := AESEnc(privKey, data) //don't need to marshall data bcz it's alread in []byte form
		FileAES := AESEnc(filePriv, FileJSON)

		//HMACs
		dataHMAC, _ := userlib.HMACEval(hmacKey, dataAES)
		FileHMAC, _ := userlib.HMACEval(hmacKey, FileAES)

		//final output
		final_data_out = append(dataAES, dataHMAC...)
		final_File_out = append(FileAES, FileHMAC...)
		userlib.DatastoreSet(storageKey, final_data_out)
		userlib.DatastoreSet(fileStorageKey, final_File_out)

		userdata.UpdateUserDatastore(userdata.Username, userdata.password)

		return
	}

	//Getting File struct and resetting Appends
	//Common to first 2 cases
	fileStorageKey = bytesToUUID([]byte(storageKey.String() + "meta"))
	retrived, _ := userlib.DatastoreGet(fileStorageKey)
	retHMAC := retrived[len(retrived)-64:]
	retVal := retrived[:len(retrived)-64]

	correctHMAC, _ := userlib.HMACEval(hmacKey, retVal)
	integrity := userlib.HMACEqual(retHMAC, correctHMAC)
	if !integrity {
		userlib.DebugMsg("STOP! File has been tampered with!")
		err = errors.New("STOP! File has been tampered with")
		return err
	}
	var filePtr *File
	file_struct_bytes := AESDec(filePriv, retVal)
	err = json.Unmarshal(file_struct_bytes, &filePtr)
	if err != nil {
		err = errors.New("unmarshalling not done")
		return err
	}

	filePtr.Appends = 0

	//Encrypting File struct
	FileJSON, _ := json.Marshal(filePtr)
	FileAES := AESEnc(filePriv, FileJSON)
	FileHMAC, _ := userlib.HMACEval(hmacKey, FileAES)
	final_File_out = append(FileAES, FileHMAC...)

	userlib.DatastoreSet(fileStorageKey, final_File_out)

	userdata.UpdateUserDatastore(userdata.Username, userdata.password)

	return

}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	// Need to first get the latest user state from datastore
	userdata.UpdateUserMaps(userdata.Username, userdata.password)

	//checking if the file exists
	var present bool
	_, present = userdata.FileName_UUId[filename]
	if !present {
		err = errors.New("file not found")
		return err
	}

	var fileID uuid.UUID
	var storageKey uuid.UUID
	var fileStorageKey uuid.UUID
	var hmacKey []byte
	var filePriv []byte
	var priv []byte

	//case for if file is a shared file
	var shared bool
	_, shared = userdata.FileUUID_FilePriv[userdata.FileName_UUId[filename]]
	if !shared {
		//This is a shared file. Need to get Share struct first
		fileID = userdata.FileName_UUId[filename]
		shareID := userdata.Shares[fileID]
		shareRandBytes := userdata.ShareBytes[shareID]

		//getting the Share struct
		got, success := userlib.DatastoreGet(shareID)
		if !success {
			userlib.DebugMsg("Couldn't get Share struct. Either revoked by owner or maliciously attacked")
			err = errors.New("couldn't get Share struct. either revoked by owner or maliciously attacked")
			delete(userdata.FileName_UUId, filename)
			delete(userdata.Shares, fileID)
			delete(userdata.ShareBytes, shareID)
			return err
		}
		if len(got)-64 <= 0 {
			userlib.DebugMsg("Datastore attack detected!")
			err = errors.New("datastore attack detected")
			return err
		}

		shareHMAC := got[len(got)-64:] //PANIC
		shareAES := got[:len(got)-64]

		sharePriv := userlib.Argon2Key(shareRandBytes, []byte(shareID.String()), 16)
		shareHmacKey := userlib.Argon2Key([]byte(shareID.String()), shareRandBytes, 16)
		correctHMAC, _ := userlib.HMACEval(shareHmacKey, shareAES)

		verify := userlib.HMACEqual(shareHMAC, correctHMAC)
		if !verify {
			userlib.DebugMsg("STOP! Share has been tampered with!")
			err = errors.New("stop! share has been tampered with")
			return err
		}

		shareBytes := AESDec(sharePriv, shareAES)

		var newShare *Share
		badJson := json.Unmarshal(shareBytes, &newShare)
		if badJson != nil {
			userlib.DebugMsg("Something wrong with Share bytes received")
			err = badJson
			return err
		}

		//time to get the file itself
		storageKey = newShare.FileUID
		hmacKey = newShare.HmacKey
		filePriv = newShare.FilePriv
		priv = newShare.Priv

		if len(hmacKey) != 16 {
			userlib.DebugMsg("STOP! Share has been tampered with!")
			err = errors.New("stop! share has been tampered with")
			return err
		}

	} else {
		storageKey = userdata.FileName_UUId[filename]

		//getting the hmac, and filePriv key
		hmacKey = userdata.FileUUID_hmac[storageKey]
		filePriv = userdata.FileUUID_FilePriv[storageKey]
		priv = userdata.FileUUID_priv[storageKey]
	}
	fileStorageKey = bytesToUUID([]byte(storageKey.String() + "meta"))

	//GETTING THE FILE STRUCT TO ADD APPEND
	retrived, _ := userlib.DatastoreGet(fileStorageKey)

	if len(retrived)-64 <= 0 {
		userlib.DebugMsg("Datastore attack detected!")
		err = errors.New("datastore attack detected")
		return err
	}

	retHMAC := retrived[len(retrived)-64:]
	retVal := retrived[:len(retrived)-64]

	correctHMAC, _ := userlib.HMACEval(hmacKey, retVal)
	integrity := userlib.HMACEqual(retHMAC, correctHMAC)
	if !integrity {
		userlib.DebugMsg("STOP! File has been tampered with!")
		err = errors.New("STOP! File has been tampered with")
		return err
	}
	var filePtr *File
	file_struct_bytes := AESDec(filePriv, retVal)
	err = json.Unmarshal(file_struct_bytes, &filePtr)
	if err != nil {
		err = errors.New("unmarshalling not done")
		return err
	}

	//ENCRYPTING AND STORING THE APPENDS
	i := filePtr.Appends
	first10 := storageKey[:10]
	appendIDBytes := append(first10, []byte(strconv.Itoa(i))...)
	j := len(appendIDBytes)
	str := ""
	for j < 16 {
		str = str + "A"
		j++
	}
	appendIDBytes = append(appendIDBytes, []byte(str)...)
	appendID := bytesToUUID(appendIDBytes)

	appendEnc := AESEnc(priv, data)
	appendHMACVal, err := userlib.HMACEval(hmacKey, appendEnc)
	if err != nil {
		return err
	}

	final_append_bytes := append(appendEnc, appendHMACVal...)

	filePtr.Appends++

	FileJSON, _ := json.Marshal(filePtr)
	FileAES := AESEnc(filePriv, FileJSON)
	FileHMAC, _ := userlib.HMACEval(hmacKey, FileAES)
	final_File_out := append(FileAES, FileHMAC...)

	userlib.DatastoreSet(fileStorageKey, final_File_out)
	userlib.DatastoreSet(appendID, final_append_bytes)
	userdata.UpdateUserDatastore(userdata.Username, userdata.password)

	return err
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	// Need to first get the latest user state from datastore
	userdata.UpdateUserMaps(userdata.Username, userdata.password)

	//checking if the file exists
	var present bool
	_, present = userdata.FileName_UUId[filename]
	if !present {
		err = errors.New("file not found")
		return nil, err
	}

	var fileID uuid.UUID
	var storageKey uuid.UUID
	var fileStorageKey uuid.UUID
	var privKey []byte
	var hmacKey []byte
	var filePriv []byte

	//case for if file is a shared file
	var shared bool
	_, shared = userdata.FileUUID_FilePriv[userdata.FileName_UUId[filename]]
	if !shared {
		//This is a shared file. Need to get Share struct first
		fileID = userdata.FileName_UUId[filename]
		shareID := userdata.Shares[fileID]
		shareRandBytes := userdata.ShareBytes[shareID]

		// fmt.Println("inside load: ", userdata.Username, shareID)

		//getting the Share struct
		got, success := userlib.DatastoreGet(shareID)
		if !success {
			userlib.DebugMsg("Couldn't get Share struct. Either revoked by owner or maliciously attacked")
			err = errors.New("couldn't get Share struct. either revoked by owner or maliciously attacked")
			delete(userdata.FileName_UUId, filename)
			delete(userdata.Shares, fileID)
			delete(userdata.ShareBytes, shareID)
			return nil, err
		}
		if len(got)-64 <= 0 {
			userlib.DebugMsg("Datastore attack detected!")
			err = errors.New("datastore attack detected")
			return dataBytes, err
		}

		shareHMAC := got[len(got)-64:] //PANIC
		shareAES := got[:len(got)-64]

		sharePriv := userlib.Argon2Key(shareRandBytes, []byte(shareID.String()), 16)
		shareHmacKey := userlib.Argon2Key([]byte(shareID.String()), shareRandBytes, 16)
		correctHMAC, _ := userlib.HMACEval(shareHmacKey, shareAES)

		verify := userlib.HMACEqual(shareHMAC, correctHMAC)
		if !verify {
			userlib.DebugMsg("STOP! Share has been tampered with!")
			err = errors.New("stop! share has been tampered with")
			return nil, err
		}

		shareBytes := AESDec(sharePriv, shareAES)

		var newShare *Share
		badJson := json.Unmarshal(shareBytes, &newShare)
		if badJson != nil {
			userlib.DebugMsg("Something wrong with Share bytes received")
			err = badJson
			return nil, err
		}

		//time to get the file itself
		storageKey = newShare.FileUID
		privKey = newShare.Priv
		hmacKey = newShare.HmacKey
		filePriv = newShare.FilePriv

		if len(hmacKey) != 16 {
			userlib.DebugMsg("STOP! Share has been tampered with!")
			err = errors.New("stop! share has been tampered with")
			return nil, err
		}

	} else {
		storageKey = userdata.FileName_UUId[filename]

		//getting the hmac, and privatekey
		privKey = userdata.FileUUID_priv[storageKey]
		hmacKey = userdata.FileUUID_hmac[storageKey]
		filePriv = userdata.FileUUID_FilePriv[storageKey]
	}
	fileStorageKey = bytesToUUID([]byte(storageKey.String() + "meta"))

	//getting the raw bytes from datastore
	var gotten []byte
	gotten, _ = userlib.DatastoreGet(storageKey)

	if len(gotten)-64 <= 0 {
		userlib.DebugMsg("Datastore attack detected!")
		err = errors.New("datastore attack detected")
		return dataBytes, err
	}

	//getting the hmac and data bytes
	gotHMAC := gotten[len(gotten)-64:] //PANIC check
	gotVal := gotten[:len(gotten)-64]
	validHMAC, at := userlib.HMACEval(hmacKey, gotVal) //PANIC check
	if at != nil {
		userlib.DebugMsg("Something wrong in Load file (shared)!")
		err = errors.New("something wrong in load file")
		return nil, err
	}

	//integrity check
	clean := userlib.HMACEqual(gotHMAC, validHMAC)
	if !clean {
		userlib.DebugMsg("STOP! File has been tampered with!")
		err = errors.New("STOP! File has been tampered with")
		return nil, err
	}

	//decrypting the file
	dataBytes = AESDec(privKey, gotVal)

	//GETTING THE FILE STRUCT TO CHECK FOR APPENDS
	retrived, _ := userlib.DatastoreGet(fileStorageKey)

	if len(retrived)-64 <= 0 {
		userlib.DebugMsg("Datastore attack detected!")
		err = errors.New("datastore attack detected")
		return dataBytes, err
	}

	retHMAC := retrived[len(retrived)-64:] //PANIC check
	retVal := retrived[:len(retrived)-64]

	correctHMAC, _ := userlib.HMACEval(hmacKey, retVal)
	integrity := userlib.HMACEqual(retHMAC, correctHMAC)
	if !integrity {
		userlib.DebugMsg("STOP! File has been tampered with!")
		err = errors.New("STOP! File has been tampered with")
		return nil, err
	}
	var filePtr *File
	file_struct_bytes := AESDec(filePriv, retVal)
	err = json.Unmarshal(file_struct_bytes, &filePtr)
	if err != nil {
		err = errors.New("unmarshalling not done")
		return nil, err
	}

	//fmt.Println(filePtr.Shares)
	_, userInShare := filePtr.Shares[userdata.Username]
	if !userInShare && filePtr.Owner != userdata.Username {
		err = errors.New("unauthorized user trying to access the file.")
		return nil, err
	}

	appends := filePtr.Appends
	i := 0
	//appendPresent := true
	for i < appends {
		first10 := storageKey[:10]
		appendIDBytes := append(first10, []byte(strconv.Itoa(i))...)
		j := len(appendIDBytes)
		str := ""
		for j <= 16 {
			str = str + "A"
			j++
		}
		appendIDBytes = append(appendIDBytes, []byte(str)...)
		appendID := bytesToUUID(appendIDBytes)
		appRetrived, appendPresent := userlib.DatastoreGet(appendID)
		if !appendPresent {
			return
		}
		if len(appRetrived)-64 <= 0 {
			userlib.DebugMsg("Datastore attack detected!")
			err = errors.New("datastore attack detected")
			return dataBytes, err
		}
		appRetHMAC := appRetrived[len(appRetrived)-64:] //PANIC check
		appRetVal := appRetrived[:len(appRetrived)-64]

		appCorrectHMAC, _ := userlib.HMACEval(hmacKey, appRetVal)
		goodAppend := userlib.HMACEqual(appCorrectHMAC, appRetHMAC)
		if !goodAppend {
			userlib.DebugMsg("STOP! File has been tampered with!")
			err = errors.New("STOP! File has been tampered with")
			return nil, err
		}

		newBytes := AESDec(privKey, appRetVal)
		dataBytes = append(dataBytes, newBytes...)
		i++
	}

	userdata.UpdateUserDatastore(userdata.Username, userdata.password)

	return dataBytes, err
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (accessToken uuid.UUID, err error) {

	// Need to first get the latest user state from datastore
	userdata.UpdateUserMaps(userdata.Username, userdata.password)

	// temp := userdata.FileName_UUId[filename]
	// temp2 := userdata.Shares[temp]
	// fmt.Println("beginning of sharefunc: ", userdata.Username, temp2)

	newFileUID, present := userdata.FileName_UUId[filename]
	if !present {
		err = errors.New("file not present in User's filespace")
		return uuid.Nil, err
	}

	if recipient == userdata.Username {
		err = errors.New("can't share file with yourself")
		return uuid.Nil, err
	}

	// fmt.Println("this user: ", userdata.Username, "to", recipient)

	_, success := userlib.KeystoreGet(recipient + "RS")
	if !success {
		userlib.DebugMsg("Invalid User. Phantom or corrupted")
		err = errors.New("invalid user. phantom or corrupted")
		return uuid.Nil, err
	}

	tokenUUID := RandomUUID()
	//stuff to save and encrypt the Share object. To be sent to
	//receiver as part of the RSA message
	shareDsUUID := RandomUUID()              //Share struct's datastore key
	tokenEncBytes := userlib.RandomBytes(16) //random bytes to make AES and HMAC key for Share

	//initializing the Token struct
	var token *Token = new(Token)
	token.EncBt = tokenEncBytes //random bytes to make AES and HMAC key for Share
	token.ShUID = shareDsUUID   //Share struct's datastore key
	token.Acc = true            //file is not revoked

	tokenBytes, _ := json.Marshal(token)

	var recipientPubKey userlib.PublicKeyType
	var worked bool
	recipientPubKey, worked = userlib.KeystoreGet(recipient + "RS")
	if !worked {
		userlib.DebugMsg("Error retrieving RSA keys for reciever")
		err = errors.New("error retrieving rsa keys for reciever")
		return uuid.Nil, err
	}

	//sending the Token after enc and DSSign
	encryptedBytes, bad := userlib.PKEEnc(recipientPubKey, tokenBytes)
	if bad != nil {
		userlib.DebugMsg("Error in encryption")
		err = errors.New("error in encryption")
		return uuid.Nil, err
	}
	dsSig, bad2 := userlib.DSSign(userdata.DSPrivateKey, encryptedBytes)
	if bad2 != nil {
		userlib.DebugMsg("Error in signing")
		err = errors.New("error in signing")
		return uuid.Nil, err
	}

	//fmt.Println("enc share: ", encryptedBytes)

	final_Token_out := append(encryptedBytes, dsSig...)

	//Decrypting the File Struct to make changes there
	copyMe := newFileUID.String()[:]
	fileDatastoreID := bytesToUUID([]byte(copyMe + "meta"))
	retrived, _ := userlib.DatastoreGet(fileDatastoreID)

	if len(retrived)-64 <= 0 {
		userlib.DebugMsg("Datastore attack detected!")
		err = errors.New("datastore attack detected")
		return uuid.Nil, err
	}

	retHMAC := retrived[len(retrived)-64:] //PANIC check
	retVal := retrived[:len(retrived)-64]

	var filePriv []byte
	var fileHmacKey []byte
	var privKey []byte
	_, owned := userdata.FileUUID_hmac[newFileUID]
	if !owned {
		filePriv, fileHmacKey, privKey, _ = userdata.GetFileFromShare(filename)
		if len(fileHmacKey) != 16 {
			err = errors.New("file is probably revoked, or DS tampered with")
			return uuid.Nil, err
		}

		// temp := userdata.FileName_UUId[filename]
		// temp2 := userdata.Shares[temp]
		// fmt.Println("back in sharefunc: ", userdata.Username, temp2)
	} else {
		filePriv = userdata.FileUUID_FilePriv[newFileUID]
		fileHmacKey = userdata.FileUUID_hmac[newFileUID]
		privKey = userdata.FileUUID_priv[newFileUID]
	}
	correctHMAC, err := userlib.HMACEval(fileHmacKey, retVal)

	integrity := userlib.HMACEqual(retHMAC, correctHMAC)
	if !integrity {
		userlib.DebugMsg("STOP! File has been tampered with!")
		err = errors.New("STOP! File has been tampered with")
		return uuid.Nil, err
	}
	var filePtr *File
	file_struct_bytes := AESDec(filePriv, retVal)
	err = json.Unmarshal(file_struct_bytes, &filePtr)
	if err != nil {
		err = errors.New("unmarshalling not done")
		return uuid.Nil, err
	}
	toFileTokenBytes, _ := json.Marshal(token)

	//Creating the share tree inside the File struct
	sharesMap := filePtr.Shares
	owner := filePtr.Owner
	filePtr.Shares = addToTree(recipient, userdata.Username, sharesMap, owner)

	//adding the token to the Tokens map in File
	filePtr.Tokens[recipient] = toFileTokenBytes
	filePtr.AccessIDs[recipient] = tokenUUID

	//Creating the Share struct with file share data
	var shareObj *Share = new(Share)
	shareObj.FileUID = newFileUID
	shareObj.Priv = privKey
	shareObj.HmacKey = fileHmacKey
	shareObj.FilePriv = filePriv
	shareObj.TokenID = tokenUUID

	sharePrivKey := userlib.Argon2Key(token.EncBt, []byte(token.ShUID.String()), 16)
	shareHMACKey := userlib.Argon2Key([]byte(token.ShUID.String()), token.EncBt, 16)

	shareBytes, _ := json.Marshal(shareObj)

	shareAES := AESEnc(sharePrivKey, shareBytes)
	shareHMAC, _ := userlib.HMACEval(shareHMACKey, shareAES)

	final_share_out := append(shareAES, shareHMAC...)

	//updating the owner (also sharer) User struct's Shares and ShareBytes maps
	//with the details on the Share struct UUID and Share struct bytes

	// if !owned { //case for when this user is not the file's owner
	// 	fmt.Println("YEEEEEEEEET")
	// 	userdata.Shares[newFileUID] = token.ShUID
	// 	userdata.ShareBytes[token.ShUID] = token.EncBt
	// } //If not the owner, then ignore and proceed normally.

	//preparing to send the File struct to datastore
	fileJSON, _ := json.Marshal(filePtr)

	fileAES := AESEnc(filePriv, fileJSON)
	fileHMAC, _ := userlib.HMACEval(fileHmacKey, fileAES)

	final_File_out := append(fileAES, fileHMAC...)

	//sending all the struct's to the datastore
	userlib.DatastoreSet(tokenUUID, final_Token_out)
	userlib.DatastoreSet(shareDsUUID, final_share_out)
	userlib.DatastoreSet(fileDatastoreID, final_File_out)

	accessToken = tokenUUID

	userdata.UpdateUserDatastore(userdata.Username, userdata.password)

	// fmt.Println("end of share: ", recipient, shareDsUUID)
	// fmt.Println("Sharer's ShareID: ", userdata.Username, userdata.Shares[userdata.FileName_UUId[filename]])

	// fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	// fmt.Println(" ")
	return accessToken, err
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string, accessToken uuid.UUID) error {

	// Need to first get the latest user state from datastore
	userdata.UpdateUserMaps(userdata.Username, userdata.password)

	var overwrite bool
	_, overwrite = userdata.FileName_UUId[filename]
	if overwrite {
		//making sure if file was shared earlier and then revoked
		fileID := userdata.FileName_UUId[filename]
		shareID := userdata.Shares[fileID]
		_, success := userlib.DatastoreGet(shareID)
		if success { //success means file is still shared
			userlib.DebugMsg("filename already exists")
			err := errors.New("filename already exists")
			return err
		} //else file was shared then revoked

	}

	//Begin the receive function
	token_raw, gotten := userlib.DatastoreGet(accessToken)
	if !gotten {
		err := errors.New("issue getting token from datastore")
		return err
	}

	token_enc := token_raw[:256]
	dsSig := token_raw[256:]

	//getting sender's public key and verifiying if the message was sent by the right person
	senderKey, _ := userlib.KeystoreGet(sender + "DS")

	signVerify := userlib.DSVerify(senderKey, token_enc, dsSig)
	if signVerify != nil {
		userlib.DebugMsg("Wrong Person sending this file/ message tampered with")
		err := signVerify
		return err
	}

	token_dec, err := userlib.PKEDec(userdata.RSPrivateKey, token_enc)
	if err != nil {
		userlib.DebugMsg("Message couldn't be decrypted well")
		return err
	}

	var tokenPtr *Token
	err = json.Unmarshal(token_dec, &tokenPtr)
	if err != nil {
		userlib.DebugMsg("Something wrong with message bytes received")
		return err
	}
	//fmt.Println("token dec out: ", tokenPtr.Fid)

	shareUID := tokenPtr.ShUID
	shareRandBytes := tokenPtr.EncBt
	access := tokenPtr.Acc
	//checking to see if owner has revoked access.
	//if access is false, owner has revoked access.
	if !access {
		err = errors.New("owner has revoked access")
		return err
	}

	got, success := userlib.DatastoreGet(shareUID)
	if !success {
		userlib.DebugMsg("Couldn't get Share struct. Either revoked by owner to maliciously attacked")
		err = errors.New("couldn't get Share struct. either revoked by owner to maliciously attacked")
		return err
	}

	// fmt.Println("share byte2: ", got[:len(got)-64])

	shareHMAC := got[len(got)-64:]
	shareAES := got[:len(got)-64]

	sharePriv := userlib.Argon2Key(shareRandBytes, []byte(tokenPtr.ShUID.String()), 16)
	shareHmacKey := userlib.Argon2Key([]byte(tokenPtr.ShUID.String()), shareRandBytes, 16)
	correctHMAC, _ := userlib.HMACEval(shareHmacKey, shareAES)

	verify := userlib.HMACEqual(shareHMAC, correctHMAC)
	if !verify {
		userlib.DebugMsg("STOP! Share has been tampered with!")
		err = errors.New("stop! share has been tampered with")
		return err
	}

	shareBytes := AESDec(sharePriv, shareAES)

	var newShare *Share
	badJson := json.Unmarshal(shareBytes, &newShare)
	if badJson != nil {
		userlib.DebugMsg("Something wrong with Share bytes received")
		err = badJson
		return err
	}

	userdata.FileName_UUId[filename] = newShare.FileUID
	// userdata.FileUUID_priv[newShare.FileUID] = newShare.Priv
	// userdata.FileUUID_hmac[newShare.FileUID] = newShare.HmacKey
	// userdata.FileUUID_FilePriv[newShare.FileUID] = newShare.FilePriv
	userdata.Shares[newShare.FileUID] = tokenPtr.ShUID
	userdata.ShareBytes[tokenPtr.ShUID] = tokenPtr.EncBt

	userdata.UpdateUserDatastore(userdata.Username, userdata.password)

	// fmt.Println("received userdata map", userdata.FileName_UUId)

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {

	userdata.UpdateUserMaps(userdata.Username, userdata.password)

	//checking if file is in the User's filespace
	var available bool
	_, available = userdata.FileName_UUId[filename]
	if !available {
		err = errors.New("file not in user's filespace")
		return err
	}

	storageKey := userdata.FileName_UUId[filename]

	//checking if User owns this file
	var owned bool
	_, owned = userdata.FileUUID_FilePriv[storageKey]
	if !owned {
		err = errors.New("file not owned by this User")
		return err
	}

	//getting the File struct for this file
	fileStorageKey := bytesToUUID([]byte(storageKey.String() + "meta"))
	filePriv := userdata.FileUUID_FilePriv[storageKey]
	fileHmacKey := userdata.FileUUID_hmac[storageKey]

	retrived, _ := userlib.DatastoreGet(fileStorageKey)

	if len(retrived)-64 <= 0 {
		userlib.DebugMsg("Datastore attack detected!")
		err = errors.New("datastore attack detected")
		return err
	}

	retHMAC := retrived[len(retrived)-64:]
	retVal := retrived[:len(retrived)-64]

	correctHMAC, _ := userlib.HMACEval(fileHmacKey, retVal)
	integrity := userlib.HMACEqual(retHMAC, correctHMAC)
	if !integrity {
		userlib.DebugMsg("STOP! File has been tampered with!")
		err = errors.New("STOP! File has been tampered with")
		return err
	}
	var filePtr *File
	file_struct_bytes := AESDec(filePriv, retVal)
	err = json.Unmarshal(file_struct_bytes, &filePtr)
	if err != nil {
		err = errors.New("unmarshalling not done")
		return err
	}

	shareMapping := filePtr.Shares
	toDelete := shareMapping[targetUsername]

	// fmt.Println("share mapping before: ", shareMapping)

	i := 1
	for i < len(toDelete) {
		target := toDelete[i]
		targetToken := filePtr.Tokens[target]
		tokenUID := filePtr.AccessIDs[target]

		_, targetPresent := filePtr.Shares[target]
		if !targetPresent {
			i++
			continue
		}

		err = userdata.revokeHelper(target, filename, targetToken, tokenUID)
		if err != nil {
			err = errors.New("couldn't finish revoke")
			return err
		}
		delete(filePtr.Shares, target)
		delete(filePtr.Tokens, target)
		delete(filePtr.AccessIDs, target)
		i++
	}
	finalToken := filePtr.Tokens[targetUsername]
	finalAccessID := filePtr.AccessIDs[targetUsername]
	err = userdata.revokeHelper(targetUsername, filename, finalToken, finalAccessID)
	if err != nil {
		err = errors.New("couldn't finish revoke")
		return err
	}
	delete(filePtr.Shares, targetUsername)
	delete(filePtr.Tokens, targetUsername)
	delete(filePtr.AccessIDs, targetUsername)

	//SENDING FILE STRUCT BACK TO DATASTORE
	fileJSON, _ := json.Marshal(filePtr)
	fileAES := AESEnc(filePriv, fileJSON)
	fileHMAC, _ := userlib.HMACEval(fileHmacKey, fileAES)
	final_File_out := append(fileAES, fileHMAC...)

	userlib.DatastoreSet(fileStorageKey, final_File_out)

	userdata.UpdateUserDatastore(userdata.Username, userdata.password)

	return
}
