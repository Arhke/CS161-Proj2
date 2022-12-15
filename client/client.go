package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	UserName string
	password string
	passHash []byte
	PrivateKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
	FileInfo   [99]Fileinfo // I change
	NextFileInfo int   // I also change
}
type Filemeta struct {
	SymmetricKey  []byte 
	MacKey      []byte
	SignKey     userlib.DSSignKey
	VerifyKey   userlib.DSVerifyKey
	Name       string 
	Owner 	   string
}
type Invitation struct{
	Name string
	Sender string
	SymmetricKey []byte
	MacKey []byte
}
type Filemetameta struct{
	MacKey []byte
	EncryptKey userlib.PKEEncKey
	Sent string
}
type Fileinfo struct {
	Sender string
	FileMeta Filemeta
	FileMetaMeta [99]Filemetameta
	NextFileMetaMeta int
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	//Initialize User Struct
	var userdata User
	userdata.UserName = username
	userdata.password = password
	userdata.passHash = userlib.Hash([]byte(password))
	sk, sign, err := InitUserKeys(username)
	userdata.PrivateKey = sk
	userdata.SignKey = sign
	userdata.NextFileInfo = 0;
	//store user struct
	UUID, err := GetUserUUID(username, password)
	if err != nil {
		return &userdata, err 
	}
	userbytes, err := SecureUser(&userdata)
	if err != nil {
		return &userdata, err
	}
	userlib.DatastoreSet(UUID, userbytes)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	
	var userdata User
	fmt.Println("========================NOTICE ME (GetUser) =========================")
	fmt.Println(1)
	UUID, err := GetUserUUID(username, password)
	if err != nil {
		return &userdata, err 
	}
	fmt.Println(2)
	userbytes, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return &userdata, errors.New("Was Unable to Retrieve User Data")
	}
	fmt.Println(3)
	
	return CheckUser(username, password, userbytes) 
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.UserName))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.UserName))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//don't need to verify it is from owner, only owner can generate a readable key for subuser
	// need to make sure the user can't modify the file. 
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// grab the reading key from the invitation
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//decrypt file data and reencrypt with a key that is not shared with said user. 
	return nil
}



//==============<Securing Helpers>============
// 

//==================<User>======================
func GenUserKey (username string, passHash []byte) []byte{
	return userlib.Argon2Key(passHash, []byte(username + "/Key"), 16)
}
func GenUserMac(username string, passHash []byte) []byte{
	return userlib.Argon2Key(passHash, []byte(username + "/Mac"), 16)
}
func InitUserKeys(username string) (private userlib.PKEDecKey, signature userlib.DSSignKey, err error) {

	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	var verify userlib.DSVerifyKey
	var sign userlib.DSSignKey
	signUUID, signError := GetUserSignUUID(username)
	if signError != nil {
		return sk, sign, signError
	}
	publicUUID, publicError := GetUserPublicUUID(username)
	if publicError != nil {
		return sk, sign, publicError
	}
	pk, sk, publicKeyGenError := userlib.PKEKeyGen()
	if publicKeyGenError != nil {
		return sk, sign, publicKeyGenError
	}
	sign, verify, signKeyGenError := userlib.DSKeyGen()
	if signKeyGenError != nil {
		return sk, sign, signKeyGenError
	}
	signStoreError := userlib.KeystoreSet(signUUID, verify)
	if signStoreError != nil {
		return sk, sign, err
	}
	publicStoreError := userlib.KeystoreSet(publicUUID, pk)
	if publicStoreError != nil {
		return sk, sign, err
	}
	return sk, sign, nil
}
func SecureUser(userdata *User)(result []byte, err error){
	ret, err := json.Marshal(userdata)
	if err != nil {
		return ret, err
	}
	var sign Signature
	sign, err = MsgToSign(userdata.SignKey, ret)
	if err != nil {
		return ret, err
	}
	ret, err = json.Marshal(sign)
	if err != nil {
		return ret, err
	}
	ret = MsgToEncrypt(GenUserKey(userdata.UserName, userdata.passHash), ret)
	macStruct, err := MsgToMac(GenUserMac(userdata.UserName, userdata.passHash), ret)
	if err != nil {
		return ret, err
	}
	ret, err = json.Marshal(macStruct)
	if err != nil {
		return ret, err
	}
	return ret,  nil
}
func CheckUser(username string, password string, content []byte)(userStruct *User, err error){
	var userdata User
	var mac Mac
	err = json.Unmarshal(content, &mac)
	if err != nil {
		return &userdata, err
	}
	content = mac.Msg
	content = DecryptToMsg(GenUserKey(username, userlib.Hash([]byte(password))), content)
	var sign Signature
	err = json.Unmarshal(content, &sign)
	if err != nil {
		return &userdata, err
	}
	var verifyKey userlib.DSVerifyKey
	verifyID, err := GetUserSignUUID(username)
	if err != nil {
		return &userdata, err
	}
	verifyKey, ok := userlib.KeystoreGet(verifyID)
	if !ok {
		return &userdata, errors.New("No Verify Key!")
	}
	content, err = SignToMsg(verifyKey, sign)
	if err != nil {
		return &userdata, err
	}
	err = json.Unmarshal(content, &userdata)
	if err != nil {
		return &userdata, err
	}
	return &userdata,  nil
}






























































//==================<KeyStore>===============
func GetUserSignUUID(username string) (usersignUUID string, err error) {
	signUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "/Signature"))[:16])
	return signUUID.String(), err
}
func GetUserPublicUUID(username string) (usersignUUID string, err error) {
	signUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "/PublicKey"))[:16])
	return signUUID.String(), err
}

//=================<DataStore>==============
/*
 * For User Struct
 */
func GetUserUUID(username string, password string) (userpassPtr uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash(userlib.Hash([]byte(username + password)))[:16])
}
/*
 * For the first File Part String
 */
func GetFileUUID(owner string, filename string) (userpassPtr uuid.UUID, err error) {
	return GetFilePartUUID(owner, filename, 0)
}
/*
 * For a File Part String
 */
func GetFilePartUUID(owner string, filename string, part int) (userpassPtr uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(owner + filename + "/" + string(part)))[:16])
}
/*
 * Next Uninitialized file part integer UUID
 */
func GetNextPartUUID(owner string, filename string) (userpassPtr uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(owner + filename + "/NextPart"))[:16])
}
/*
 * Get FileMeta struct
 */
func GetFileMetaUUID(owner string, filename string, user string) (userpassPtr uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(user + owner + filename))[:16])
}
/*
 * Invitation struct
 */
func GetInvitationUUID(user string, filename string, sender string) (userpassPtr uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(user + sender + filename))[:16])
}








































//==================<Sign>================
type Signature struct {
	Msg []byte
	Sign []byte
}
func MsgToSign (signKey userlib.DSSignKey, msg []byte)(signature Signature, err error){
	var sign Signature
	sign.Msg = msg
	signBytes, err := userlib.DSSign(signKey, msg)
	if err != nil {
		return sign, err
	}
	sign.Sign = signBytes
	return sign, err
}
func SignToMsg (verifyKey userlib.DSVerifyKey, signature Signature)(msg []byte, err error){
	err = userlib.DSVerify(verifyKey, signature.Msg, signature.Sign)
	if err != nil{
		return []byte(""), err
	}

	return signature.Msg, nil
}

//==================<Encrypt>=================
func MsgToEncrypt (key []byte, plaintxt []byte) []byte {
	iv := userlib.RandomBytes(16)
	return userlib.SymEnc(key, iv, plaintxt)
}
func DecryptToMsg (key []byte, ciphertxt []byte) []byte {
	//Hmac covers panic cases
	return userlib.SymDec(key, ciphertxt)
}
//====================<HMac>==================
/*
 * The Mac Keys are 16 byte symmetric
 */
type Mac struct {
	Msg  []byte
	HMAC []byte
}
func MsgToMac(key []byte, msg []byte) (mac Mac, err error){ 
	var ret Mac
	ret.Msg = msg
	ret.HMAC, err = userlib.HMACEval(key, msg)
	if (err != nil){
		return ret, err
	}
	return ret, nil
}
func VerifyMsgIntegrity(key []byte, mac Mac) (ok bool, err error) {
	newHMAC, err := userlib.HMACEval(key, []byte(mac.Msg))
	if (err != nil){
		return false, err
	}
	return userlib.HMACEqual(newHMAC,mac.HMAC), nil
}//internal helper
func MacToMsg(key []byte, mac Mac) (msg []byte, err error){
	ok, err := VerifyMsgIntegrity(key, mac)
	if (err != nil){
		return []byte(""), err
	}
	if (!ok){
		return []byte(""), errors.New("Retrieval msg has been tampered with")
	}
	return mac.Msg, nil
}

