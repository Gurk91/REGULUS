package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	"errors"
	_ "errors"
	"fmt"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func getKeys(mapping map[uuid.UUID][]byte) (output []uuid.UUID) {
	output = make([]uuid.UUID, 0)
	for i, _ := range mapping {
		output = append(output, i)
	}
	return output

}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"

	t.Log("Got user", u.Username)

	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.

	getu, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"

	t.Log("Got back user", getu.Username)

}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func TestStorageMultiUser(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	//ggggg
	u2, err5 := InitUser("jacob", "fring")
	if err5 != nil {
		t.Error("Failed to initialize user", err5)
		return
	}

	v3 := []byte("This is a different file")
	u2.StoreFile("file2", v3)

	v4, err3 := u2.LoadFile("file2")
	if err3 != nil {
		t.Error("Failed to upload and download", err3)
		return
	}
	if !reflect.DeepEqual(v3, v4) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

}

func TestMultiSession(t *testing.T) {
	clear()
	f1 := []byte("content")
	f2 := []byte("different content")

	// Alice and Bob each start a users session by authenticating to the client.
	alice_session_1, _ := InitUser("user_alice", "password1")
	bob_session_1, _ := InitUser("user_bob", "password2")

	// Alice stores byte slice f1 with name "filename" and Bob stores byte slice
	// f2 also with name "filename".
	alice_session_1.StoreFile("filename", f1)
	bob_session_1.StoreFile("filename", f2)

	// Alice and Bob each confirm that they can load the file they previously
	// stored and that the file contents is the same.

	f1_loaded, _ := alice_session_1.LoadFile("filename")
	f2_loaded, _ := bob_session_1.LoadFile("filename")

	if !reflect.DeepEqual(f1, f1_loaded) {
		panic("file contents are different. 1")
	}
	if !reflect.DeepEqual(f2, f2_loaded) {
		panic("file contents are different. 2")
	}

	// Alice gets an error when trying to load a file that does not exist in her
	// namespace.
	_, err := alice_session_1.LoadFile("nonexistent")
	if err == nil {
		panic("this file shouldn't be downloaded")
	}

	// Bob creates a second user session by authenticating to the client again.
	bob_session_2, _ := GetUser("user_bob", "password2")

	// Bob stores byte slice f2 with name "newfile" using his second user
	// session.
	bob_session_2.StoreFile("newfile", f2)

	// Bob loads "newfile" using his first user session. Notice that Bob does
	// not need to reauthenticate. File changes must be available to all active
	// sessions for a given user.

	f2_newfile, _ := bob_session_1.LoadFile("newfile")

	if !reflect.DeepEqual(f2, f2_newfile) {
		t.Error("Downloaded file is not the same", f2, f2_newfile)
		panic("file contents are different. 3")
	}
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func TestStorageOverwrite(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
	//overwriting a current file with the same name.
	dup := []byte("This is yet another file")
	u.StoreFile("file1", dup)

	dup2, errdup2 := u.LoadFile("file1")
	if errdup2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(dup, dup2) {
		t.Error("Downloaded file is not the same", dup, dup2)
		return
	}

}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	// fmt.Println("test access token: ", accessToken)

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

//~~~~~~~~~~~~~~~~~~~ MORE CUSTOM TESTS ~~~~~~~~~~~~~~~~~~~

func TestReuseInitUser(t *testing.T) {
	clear()
	_, err := InitUser("Albert", "badPassword")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u, err2 := InitUser("Albert", "GoodPassword")
	if err2 == nil || u != nil {
		t.Error("Username reuse is not allowed", err2)
		return
	}
}

func TestShareTreeNoRev(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "password")
	u2, _ := InitUser("bob", "GoodPassword")
	u3, _ := InitUser("james", "gghghgh")
	u4, _ := InitUser("ooga", "g5896u6u6")

	file := []byte("I am a little stitious")
	u1.StoreFile("file1", file)

	fileBack, _ := u1.LoadFile("file1")
	if !reflect.DeepEqual(file, fileBack) {
		t.Error("Downloaded file is not the same", file, fileBack)
		return
	}

	at1, _ := u1.ShareFile("file1", "bob")
	err := u2.ReceiveFile("file2", "alice", at1)
	if err != nil {
		return
	}

	at2, _ := u1.ShareFile("file1", "james")
	err2 := u3.ReceiveFile("file3", "alice", at2)
	if err2 != nil {
		return
	}

	at3, rh := u2.ShareFile("file2", "ooga")
	if rh != nil {
		fmt.Println(u4, at3)
		return
	}

}

func TestShareTreeRevoke(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "password")
	u2, _ := InitUser("bob", "GoodPassword")
	u3, _ := InitUser("james", "gghghgh")
	u4, _ := InitUser("ooga", "g5896u6u6")

	file := []byte("I am a little stitious")
	u1.StoreFile("file1", file)

	fileBack, _ := u1.LoadFile("file1")
	if !reflect.DeepEqual(file, fileBack) {
		t.Error("Downloaded file is not the same", file, fileBack)
		return
	}

	at1, _ := u1.ShareFile("file1", "bob")
	err := u2.ReceiveFile("file2", "alice", at1)
	if err != nil {
		return
	}

	at2, _ := u1.ShareFile("file1", "james")
	err2 := u3.ReceiveFile("file3", "alice", at2)
	if err2 != nil {
		return
	}

	at3, rh := u2.ShareFile("file2", "ooga")
	if rh != nil {
		fmt.Println(u4, at3)
		return
	}

	revokeError := u1.RevokeFile("file1", "bob")
	if revokeError != nil {
		t.Error(revokeError)
		return
	}

	badLoad, loadError := u2.LoadFile("file2")
	if loadError == nil {
		err = errors.New("bob can still access revoked file")
		t.Error(err)
		return
	}
	if reflect.DeepEqual(badLoad, file) {
		err = errors.New("bob can still read revoked file")
		t.Error(err)
		return
	}

	receiveRevoked := u4.ReceiveFile("file 10", "bob", at3)
	if receiveRevoked == nil {
		err = errors.New("ooga can recieve a revoked file")
		t.Error(err)
		return
	}

	gotFile, _ := u3.LoadFile("file3")
	if !reflect.DeepEqual(gotFile, file) {
		err = errors.New("james got the wrong file!")
		t.Error(err)
		return
	}
}

func TestSingleUserAppend(t *testing.T) {
	clear()
	file1Data := []byte("File 1 data woohoo")
	file1append := []byte(" here is more yeet")
	file1dataAppend2 := []byte(" and even more!!")

	nick, _ := InitUser("Albert", "badPassword")
	nick.StoreFile("file1", file1Data)
	nick.AppendFile("file1", file1append)
	nick.AppendFile("file1", file1dataAppend2)
	outfile, _ := nick.LoadFile("file1")
	correctFile := append(file1Data, file1append...)
	correctFile = append(correctFile, file1dataAppend2...)
	if !reflect.DeepEqual(outfile, correctFile) {
		err := errors.New("append is broken")
		t.Error(err)
		fmt.Println(outfile, correctFile)
		return
	}

}

func TestMultiSessionShareAppendRevoke(t *testing.T) {
	clear()
	jan, _ := InitUser("jan", "password")
	michael, _ := InitUser("michael", "doe")
	jim, _ := InitUser("jim", "zuma")
	pam, _ := InitUser("pam", "halpert")
	dwight, _ := InitUser("dwight", "schrute")
	dwight2, _ := GetUser("dwight", "schrute")

	dwightsRights := []byte("dwight has the right to settle conflicts by physical combat.")
	dwight.StoreFile("rights", dwightsRights)
	mikeToken, err := dwight.ShareFile("rights", "michael")
	if err != nil {
		err = errors.New("error sharing file")
		t.Error(err)
		return
	}
	michael2, _ := GetUser("michael", "doe")
	michael2.ReceiveFile("dwightBS", "dwight", mikeToken)
	gottenFile, _ := michael.LoadFile("dwightBS")
	if !reflect.DeepEqual(gottenFile, dwightsRights) {
		err = errors.New("multi-user sharing is broken")
		t.Error(err)
		return
	}
	DSaddendum := []byte(" jim is forever banned from reading Dwight's rights")
	validFile := append(dwightsRights, DSaddendum...) //the correct version of Dwight's rules

	dwight2.AppendFile("rights", DSaddendum)
	got2, _ := michael2.LoadFile("dwightBS")
	if !reflect.DeepEqual(got2, validFile) {
		err = errors.New("multi-user sharing/appending is broken")
		t.Error(err)
		return
	}

	mikeFile1, _ := michael2.LoadFile("dwightBS")
	if !reflect.DeepEqual(mikeFile1, validFile) {
		err = errors.New("load after bad revoke failed")
		t.Error(err)
		return
	}

	janToken, _ := michael.ShareFile("dwightBS", "jan")
	jan.ReceiveFile("dwightBS", "michael", janToken)
	jan2, _ := jan.LoadFile("dwightBS")
	if !reflect.DeepEqual(jan2, validFile) {
		err = errors.New("multi-user sharing/appending is broken jan")
		t.Error(err)
		return
	}

	janNew, _ := GetUser("jan", "password")
	jimToken, _ := janNew.ShareFile("dwightBS", "jim")
	jim.ReceiveFile("prank", "jan", jimToken)

	newJim, _ := GetUser("jim", "zuma")
	jimFile, _ := newJim.LoadFile("prank")
	if !reflect.DeepEqual(jimFile, validFile) {
		err = errors.New("multi-user sharing/appending is broken Jim")
		t.Error(err)
		return
	}

	jimAppend := []byte(" Jim halpert is the salesman in the office")
	validFile = append(validFile, jimAppend...)

	jim.AppendFile("prank", jimAppend)
	dwight3, _ := dwight.LoadFile("rights")
	if !reflect.DeepEqual(dwight3, validFile) {
		err = errors.New("multi-user sharing/appending is broken Dwight")
		t.Error(err)
		return
	}

	pamAT, _ := michael.ShareFile("dwightBS", "pam")
	pam.ReceiveFile("dwightBS", "michael", pamAT)

	dwight.RevokeFile("rights", "jan")

	jan3, _ := jan.LoadFile("dwightBS")
	if reflect.DeepEqual(jan3, validFile) {
		err = errors.New("Jan the traitor can read Dwight's rights!")
		t.Error(err)
		return
	}

	err = jan.StoreFile("dwightBS", validFile)
	if err == nil {
		//err = errors.New("Jan the traitor can edit Dwight's rights!")
		t.Error(err)
		return
	}

	jimFile2, _ := newJim.LoadFile("prank")
	if reflect.DeepEqual(jimFile2, validFile) {
		err = errors.New("Jim can read Dwight's rights!")
		t.Error(err)
		return
	}

	badRevoke := michael.RevokeFile("dwightBS", "dwight")
	if badRevoke == nil {
		err = errors.New("michael can't fire dwight. he doesn't work at Berkeley")
		t.Error(err)
		return
	}

	ryan, _ := InitUser("ryan", "fired")
	ryanToken, _ := dwight.ShareFile("rights", "ryan")
	ryan.ReceiveFile("rights", "dwight", ryanToken)

	mikeFile, _ := michael2.LoadFile("dwightBS")
	if !reflect.DeepEqual(mikeFile, validFile) {
		err = errors.New("load after bad revoke failed")
		t.Error(err)
		return
	}

	jimFile, _ = jim.LoadFile("prank")
	if reflect.DeepEqual(jimFile, validFile) {
		err = errors.New("jim can still see dwight's file!")
		t.Error(err)
		return
	}

	pamFile, _ := pam.LoadFile("dwightBS")
	if !reflect.DeepEqual(pamFile, validFile) {
		err = errors.New("pam can't see dwight's file!")
		t.Error(err)
		return
	}

	// sharing with a user who was once revoked. share should go through smoothly
	janToken2, err := dwight.ShareFile("rights", "jan")
	if err != nil {
		t.Error("dwight couldn't reshare the file with jan")
		return
	}
	// janToken2 := uuid.New()
	err = jan.ReceiveFile("rights2", "dwight", janToken2)
	if err != nil {
		t.Error("dwight couldn't reshare the file with jan _ on receive")
		return
	}
	newShare, _ := jan.LoadFile("rights2")
	if !reflect.DeepEqual(newShare, validFile) {
		err = errors.New("jan can't see dwight's file after getting it back!")
		t.Error(err)
		return
	}

	dwight.RevokeFile("rights", "jan")

	janToken3, err := dwight.ShareFile("rights", "jan")
	if err != nil {
		t.Error("dwight couldn't reshare the file with jan")
		return
	}

	err = jan.ReceiveFile("rights2", "dwight", janToken3)
	if err != nil {
		t.Error("dwight couldn't reshare the file with jan _ on receive")
		return
	}

}

func TestOverwriteReceiveFailure(t *testing.T) {
	clear()
	jim, _ := InitUser("jim", "halpert")
	pam, _ := InitUser("pam", "beasly")
	file := []byte("jim is smart")
	jim.StoreFile("File1", file)
	token, _ := jim.ShareFile("File1", "pam")
	err := pam.ReceiveFile("File2", "jim", token)
	if err != nil {
		t.Error("Receive and rename failed")
		return
	}
	pam1, _ := pam.LoadFile("File1")
	jim1, _ := jim.LoadFile("File1")
	if reflect.DeepEqual(jim1, pam1) {
		t.Error("File should not be equal")
		return
	}
}

func TestShareRecieveFailureTests(t *testing.T) {
	clear()

	//Initization of users
	jim, _ := InitUser("jim", "halpert")
	pam, _ := InitUser("pam", "beasly")

	//Store a file for Alice
	pamsFile := []byte("Jim is the best salesman in the office")

	jim.StoreFile("file1", pamsFile)

	token, err := jim.ShareFile("file1", "pam") //good share
	if err != nil {
		t.Error("didn't return existing file")
		return
	}

	token, err = jim.ShareFile("file1", "Creed") //sharing with non-existent user
	if err == nil {
		t.Error("Can't share with Creed")
		return
	}

	err = pam.ReceiveFile("file1", "Creed", token) //getting from a non-existent user
	if err == nil {
		t.Error("Cant get from Creed")
	}

	token, err = jim.ShareFile("Creed's Brain", "pam") //sharing a file that doesn't exist
	if err == nil {
		t.Error("Cant share something doesnt exist, such as creed's brain")
		return
	}

	creedFile := []byte("www. creedthoughts. gov. com/creedthoughts ")
	jim.StoreFile("file2", creedFile)

	token, err = jim.ShareFile("file2", "pam") //good share
	if err != nil {
		t.Error("some error in sharing")
		return
	}

	token = uuid.New()                                //tampered token
	err = pam.ReceiveFile("brokenFile", "jim", token) //pam shouldn't get a tampered token
	if err == nil {
		t.Error("pam can't get a broken token")
		return
	}

}

func TestAllFailures(t *testing.T) {
	clear()
	jim, _ := InitUser("jim", "halpert")
	pam, _ := InitUser("pam", "beasly")

	_, err := InitUser("jim", "halpert")
	if err == nil {
		t.Error("jim can't init with same password and username!")
		return
	}
	_, err = InitUser("jim", "beasly")
	if err == nil {
		t.Error("jim can't init with different password and same username!")
		return
	}
	_, err = GetUser("ryan", "youngestVP@#$%")
	if err == nil {
		t.Error("ryan can't Get without Init")
		return
	}
	file1 := []byte("the dunder code")
	file2 := []byte("")
	jim.StoreFile("dunder", file1)
	pam.StoreFile("empty", file2)

	jimFile, _ := jim.LoadFile("dunder")
	if !reflect.DeepEqual(jimFile, file1) {
		t.Error("files not equal")
		return
	}
	_, err = jim.LoadFile("empty")
	if err == nil {
		t.Error("jim shouldn't see pam's file")
		return
	}

	_, err = pam.LoadFile("dunder")
	if err == nil {
		t.Error("pam shouldn't see jim's file")
		return
	}

	err = jim.AppendFile("empty", []byte("lmao you been pranked"))
	if err == nil {
		t.Error("jim shouldn't append pam's file")
		return
	}

	err = pam.AppendFile("dunder", []byte("lmao you been pranked"))
	if err == nil {
		t.Error("pam shouldn't append jim's file")
		return
	}

	_, err = jim.ShareFile("empty", "pam")
	if err == nil {
		t.Error("can't share file you don't own")
		return
	}

	_, err = jim.ShareFile("dunder", "jim")
	if err == nil {
		t.Error("can't share file wiht yourself")
		return
	}

	_, err = pam.ShareFile("dunder", "jim")
	if err == nil {
		t.Error("can't share file you don't own")
		return
	}

}

func TestDatastoreAttack1(t *testing.T) {
	clear()
	datamap := userlib.DatastoreGetMap()
	update := 0
	start := 0
	end := 0
	counter := len(datamap)
	keys := getKeys(datamap)

	InitUser("jim", "halpert")
	datamap = userlib.DatastoreGetMap()
	update = len(datamap) - counter
	start = end
	end = end + update
	counter = len(datamap)
	keys = getKeys(datamap)
	i := start
	var keyToChange uuid.UUID
	for i < end {
		keyToChange = keys[i]
		userlib.DatastoreSet(keyToChange, userlib.RandomBytes(100))
		i++
	}
	_, err := GetUser("jim", "halpert")
	if err == nil {
		t.Error("error was not detected")
		return
	}

}

// func TestBadShare(t *testing.T) {
// 	jim, _ := InitUser("jim", "halpert")
// 	pam, _ := InitUser("pam", "halpert")
// 	cathy, _ := InitUser("cathy", "simms")

// 	file1 := []byte("dear pam, I love you")
// 	pam2, _ := GetUser("pam", "halpert")
// 	jim.StoreFile("love letter", file1)
// 	pamToken, _ := jim.ShareFile("love letter", "pam")
// 	err := cathy.ReceiveFile("stolen", "jim", pamToken)
// 	if err == nil {
// 		t.Error("cathy can't steal pam's letter!")
// 		return
// 	}
// 	err = pam2.ReceiveFile("jims letter", "jim", pamToken)
// 	if err != nil {
// 		t.Error("pam didnt get the letter")
// 		return
// 	}

// 	letter, _ := pam.LoadFile("jims letter")
// 	if !reflect.DeepEqual(letter, file1) {
// 		t.Error("pam didnt get the correct letter")
// 		return
// 	}

// }

//Append Efficiency Test
// func TestAppendEfficiencySmall(t *testing.T) {
// 	clear()
// 	file1Data := []byte("A")
// 	file1append := []byte("B")

// 	fmt.Println("byte size: ", len(file1Data))
// 	fmt.Println("append size: ", len(file1append))

// 	userlib.DatastoreResetBandwidth()
// 	fmt.Println("init: ", userlib.DatastoreGetBandwidth())

// 	nick, _ := InitUser("Albert", "badPassword")
// 	nick.StoreFile("file1", file1Data)

// 	//userlib.DatastoreResetBandwidth()
// 	fmt.Println("after store: ", userlib.DatastoreGetBandwidth())

// 	userlib.DatastoreResetBandwidth()
// 	nick.AppendFile("file1", file1append)
// 	fmt.Println("after append: ", userlib.DatastoreGetBandwidth())

// 	outfile, _ := nick.LoadFile("file1")
// 	correctFile := append(file1Data, file1append...)
// 	if !reflect.DeepEqual(outfile, correctFile) {
// 		err := errors.New("append is broken")
// 		t.Error(err)
// 		fmt.Println(outfile, correctFile)
// 		return
// 	}
// }

// func TestAppendEfficiencyMedium(t *testing.T) {
// 	clear()
// 	fmt.Println(" ")

// 	file1Data := []byte("This isn't a very big file. It's just a couple of sentences tbh.")
// 	file1append := []byte("This is a slightly larger append.")

// 	fmt.Println("byte size: ", len(file1Data))
// 	fmt.Println("append size: ", len(file1append))

// 	userlib.DatastoreResetBandwidth()
// 	fmt.Println("init: ", userlib.DatastoreGetBandwidth())

// 	nick, _ := InitUser("Albert", "badPassword")
// 	nick.StoreFile("file1", file1Data)

// 	userlib.DatastoreResetBandwidth()
// 	nick.AppendFile("file1", file1append)

// 	fmt.Println("after append: ", userlib.DatastoreGetBandwidth())

// 	outfile, _ := nick.LoadFile("file1")
// 	correctFile := append(file1Data, file1append...)
// 	if !reflect.DeepEqual(outfile, correctFile) {
// 		err := errors.New("append is broken")
// 		t.Error(err)
// 		fmt.Println(outfile, correctFile)
// 		return
// 	}
// }

// func TestAppendEfficiencyLarge(t *testing.T) {
// 	clear()
// 	fmt.Println(" ")

// 	file1Data := []byte("This file is huge. It consists of the sum of human knowledge. I am honestly running out of garbage to type, but i must continue to do so. It's 4am, I've pulled 3 allnighters in a row, covid is coming back, and i cant even get vaccinated. bro what's going on tbh? I am very confused :/ rip. pleace out.")
// 	toDouble := []byte("This file is huge. It consists of the sum of human knowledge. I am honestly running out of garbage to type, but i must continue to do so. It's 4am, I've pulled 3 allnighters in a row, covid is coming back, and i cant even get vaccinated. bro what's going on tbh? I am very confused :/ rip. pleace out.")
// 	file1Data = append(file1Data, toDouble...)

// 	file1append := []byte("This append is much larger, and since idk what to write, I'll just paste this twice. This append is much larger, and since idk what to write, I'll just paste this twice. This append is much larger, and since idk what to write, I'll just paste this twice.")

// 	fmt.Println("byte size: ", len(file1Data))
// 	fmt.Println("append size: ", len(file1append))

// 	userlib.DatastoreResetBandwidth()
// 	fmt.Println("init: ", userlib.DatastoreGetBandwidth())

// 	nick, _ := InitUser("Albert", "badPassword")
// 	nick.StoreFile("file1", file1Data)
// 	userlib.DatastoreResetBandwidth()
// 	nick.AppendFile("file1", file1append)

// 	//userlib.DatastoreResetBandwidth()
// 	fmt.Println("after append: ", userlib.DatastoreGetBandwidth())
// }

// func TestAppendEfficiencyPiazza(t *testing.T) {
// 	clear()
// 	fmt.Println(" ")

// 	jim, _ := InitUser("jim", "halpert")
// 	fileA := []byte("A")
// 	fileB := []byte("B")
// 	jim.StoreFile("fileA", fileA)
// 	jim.StoreFile("fileB", fileB)

// 	userlib.DatastoreResetBandwidth()
// 	jim.AppendFile("fileA", []byte("A"))
// 	fmt.Println("append len: ", len([]byte("A")))
// 	fmt.Println(userlib.DatastoreGetBandwidth())

// 	userlib.DatastoreResetBandwidth()
// 	jim.AppendFile("fileA", []byte("AB"))
// 	fmt.Println("append len: ", len([]byte("AB")))
// 	fmt.Println(userlib.DatastoreGetBandwidth())

// 	userlib.DatastoreResetBandwidth()
// 	jim.AppendFile("fileA", []byte("ABC"))
// 	fmt.Println("append len: ", len([]byte("ABC")))
// 	fmt.Println(userlib.DatastoreGetBandwidth())

// 	userlib.DatastoreResetBandwidth()
// 	jim.AppendFile("fileA", []byte("ABCD"))
// 	fmt.Println("append len: ", len([]byte("ABCD")))
// 	fmt.Println(userlib.DatastoreGetBandwidth())

// 	userlib.DatastoreResetBandwidth()
// 	jim.AppendFile("fileA", []byte("A"))
// 	fmt.Println("append len: ", len([]byte("A")))
// 	fmt.Println(userlib.DatastoreGetBandwidth())

// 	userlib.DatastoreResetBandwidth()
// 	jim.AppendFile("fileB", []byte("B"))
// 	fmt.Println("append len: ", len([]byte("B")))
// 	fmt.Println(userlib.DatastoreGetBandwidth())

// }
