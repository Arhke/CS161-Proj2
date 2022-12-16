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
type Nextpart struct{
	NextPart int
}
type Invitation struct{ //remote only
	Name string
	Owner string
	Initial string
	SymmetricKey []byte
	MacKey []byte
}
type InvitationWrapper struct{
	Invitation []byte
	MacKey []byte
	SymmetricKey []byte
}
type Filemetameta struct{ //local only
	MacKey []byte
	SymmetricKey []byte
	Sent string
}
type Fileinfo struct {
	Name string
	Sender string //sender is self if you are owner
	FileMeta Filemeta //only used if you are owner
	FileMetaMeta [99]Filemetameta //only used if you are owner
	NextFileMetaMeta int //only used if you are owner
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
	
	return &userdata, UpdateRemoteUser(&userdata)
}
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	UUID, err := GetUserUUID(username, password)
	if err != nil {
		return &userdata, err 
	}
	userbytes, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return &userdata, errors.New("Was Unable to Retrieve User Data")
	}
	return CheckUser(username, password, userbytes) 
}

func (userdata *User) StoreFile(filename string, content []byte) error {
	err := UpdateLocalUser(userdata)
	if err != nil {
		return err
	}
	var fileinfo *Fileinfo
	fileinfo, ok := SearchFileInfo(userdata, filename)//search for file info instance
	if(ok){
		if (fileinfo.Sender == userdata.UserName){//if yes then check if user is owner
			//if is owner, try overwriting directly, then reencrypting using known params
			//don't need to change filemeta
			return UpdateRemoteFile(fileinfo.FileMeta, content, false)
		}else{
			//if not owner, search for the invitation. 
			invitation, err := CheckRemoteInvitation(userdata, fileinfo.Sender, fileinfo.Name)
			if err != nil{
				return err
			}
			filemeta, err := ReadRemoteFileMeta(invitation, userdata)
			if err != nil{
				return err
			}
			
			return UpdateRemoteFile(filemeta, content, false)

		}
	}else{
		//if not, store new file
		var newfileinfo Fileinfo
		newfileinfo.Name = filename
		newfileinfo.Sender = userdata.UserName
		newfilemeta, err:= GenFileMeta(userdata.UserName, filename)
		if err != nil {
			return err
		}
		newfileinfo.FileMeta = newfilemeta
		err = UpdateRemoteFile(newfileinfo.FileMeta, content, false)
		if err != nil {
			return err
		}
		//add new entry in file info
		userdata.FileInfo[userdata.NextFileInfo] = newfileinfo
		userdata.NextFileInfo++
		return UpdateRemoteUser(userdata)
	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	err := UpdateLocalUser(userdata)
	if err != nil {
		return err
	}
	var fileinfo Fileinfo
	fileinfo, ok := SearchFileInfo(userdata, filename)//search for file info instance
	if(ok){
		if (fileinfo.Sender == userdata.UserName){//if yes then check if user is owner
			//if is owner, try overwriting directly, then reencrypting using known params
			//don't need to change filemeta
			return UpdateRemoteFile(fileinfo.FileMeta, content, true)
		}else{
			//if not owner, search for the invitation. 
			invitation, err := CheckRemoteInvitation(userdata, fileinfo.Sender, fileinfo.Name)
			if err != nil{
				return err
			}
			filemeta, err := ReadRemoteFileMeta(invitation, userdata)
			if err != nil{
				return err
			}
			return UpdateRemoteFile(filemeta, content, true)

		}
	}else{
		return errors.New("File Does not quite exist")
	}
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	err = UpdateLocalUser(userdata)
	if err != nil {
		return []byte(""), err
	}
	var fileinfo Fileinfo
	fileinfo, ok := SearchFileInfo(userdata, filename)//search for file info instance
	if(ok){
		if (fileinfo.Sender == userdata.UserName){//if yes then check if user is owner
			//if is owner, try overwriting directly, then reencrypting using known params
			//don't need to change filemeta 

			return ReadRemoteFile(fileinfo.FileMeta)
		}else{
			//if not owner, search for the invitation. 
			invitation, err := CheckRemoteInvitation(userdata, fileinfo.Sender, fileinfo.Name)
			if err != nil{
				return []byte{},err
			}
			filemeta, err := ReadRemoteFileMeta(invitation, userdata)
			if err != nil{
				return []byte{}, err
			}
			return ReadRemoteFile(filemeta)

		}
	}else{
		return []byte{}, errors.New(strings.ToTitle("file not found"))
	}
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	err = UpdateLocalUser(userdata)

	if err != nil {
		return uuid.New(), err
	}
	var fileinfo Fileinfo
	fileinfo, ok := SearchFileInfo(userdata, filename)//search for file info instance
	if !ok {
		return uuid.New(), errors.New("You Don't have that file in your namespace")
	}
	var invitation Invitation
	if (fileinfo.Sender == userdata.UserName){
		//own file
		//gen new filemetameta
		var filemetameta Filemetameta
		filemetameta.MacKey = userlib.RandomBytes(16)
		filemetameta.SymmetricKey = userlib.RandomBytes(16)
		filemetameta.Sent = recipientUsername
		//add a new local filemetameta and increment nextfilemetameta
		fileinfo.FileMetaMeta[fileinfo.NextFileMetaMeta] = filemetameta
		fileinfo.NextFileMetaMeta++
		//save a new copy of the filemeta
		err = UpdateRemoteFileMeta(filemetameta, userdata, fileinfo.FileMeta)
		if (err != nil) {
			return uuid.New(), err
		}
		//add new remote invite update remote user struct
		invitation.Name = filename
		invitation.Owner = userdata.UserName
		invitation.Initial = recipientUsername
		invitation.SymmetricKey = filemetameta.SymmetricKey
		invitation.MacKey = filemetameta.MacKey
		retUUID, err := SendRemoteInvitation(userdata, recipientUsername, invitation)
		if (err != nil) {
			return uuid.New(), err
		}
		//update remote user
		err = UpdateRemoteUser(userdata)
		if (err != nil) {
			return uuid.New(), err
		}
		return retUUID, nil
	}else{
		invitation, err = CheckRemoteInvitation(userdata, fileinfo.Sender, filename)
		if (err != nil) {
			return uuid.New(), err
		}
		retUUID, err := SendRemoteInvitation(userdata, recipientUsername, invitation)
		if (err != nil) {
			return uuid.New(), err
		}
		return retUUID, nil
	}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	err := UpdateLocalUser(userdata)
	if err != nil {
		return err
	}
	_, ok := SearchFileInfo(userdata, filename)//search for file info instance
	if ok {
		return errors.New("You already have that file in your namespace")
	}
	//copy the UUID from the function parameter into a custom UUID
	inviteUUID, err := GetInvitationUUID(userdata.UserName, filename, senderUsername)
	if err != nil {
		return err
	}
	content, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Can't Get Invite")
	}
	userlib.DatastoreSet(inviteUUID, content)
	_, err = CheckRemoteInvitation(userdata, senderUsername, filename)
	if err != nil {
		return err
	}
	//invitation is valid initialize new fileinfo
	var newfileinfo Fileinfo
	newfileinfo.Name = filename
	newfileinfo.Sender = senderUsername
	//set fileinfo into userdata
	userdata.FileInfo[userdata.NextFileInfo] = newfileinfo
	userdata.NextFileInfo++
	//update remote user
	return UpdateRemoteUser(userdata)
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	err := UpdateLocalUser(userdata)
	if err != nil {
		return err
	}
	fileinfo, ok := SearchFileInfo(userdata, filename, recipientUsername)
	if !ok {
		return errors.New("You Don't have that file in your namespace")
	}
	if fileinfo.Sender != userdata.UserName{
		return errors.New("You Don't own the file")
	}
	fmm, ok := SearchFileMetaMeta(userdata, filename, recipientUsername)
	if !ok{
		return errors.New("The file is not shared with the specified recipient")
	}
	//change the filemetameta keyvalues
	fmm.MacKey = userlib.RandomBytes(16)
	fmm.SymmetricKey = userlib.RandomBytes(16)
	fmm.Sent = ""
	
	//generate a new FileMeta
	filemeta, err := GenFileMeta(userdata.UserName, filename)
	if err != nil {
		return err
	}
	//Reencrypt the file with the new File Meta (read then rewrite)
	content, err := ReadRemoteFile(filemeta)
	if err != nil {
		return err
	}
	err = UpdateRemoteFile(filemeta, content, false)
	if err != nil {
		return err
	}
	//Update the RemoteFileMetas
	fileinfo, _ := SearchFileInfoPtr(userdata, filename)
	fileinfo.FileMeta = filemeta //update local filemeta
	for i := 0; i < fileinfo.NextFileMetaMeta; i++ {
		filemetameta := fileinfo.FileMetaMeta[i]
		err = UpdateRemoteFileMeta(filemetameta, userdata, filemeta)
		if err != nil {
			return err
		}
		
	}
	//Update Remote User
	return UpdateRemoteUser(userdata)
}


//==========================<Invitation>=====================
func SendRemoteInvitation(userdata *User, to string, invitation Invitation)  (id uuid.UUID, err error) {
	content := []byte{}
	content, err = json.Marshal(invitation)
	if err != nil {
		return uuid.New(), err
	}
	var sign Signature
	sign, err = MsgToSign(userdata.SignKey, content)
	if err != nil {
		return uuid.New(), err
	}
	content, err = json.Marshal(sign)
	if err != nil {
		return uuid.New(), err
	}
	symmetrickey:=userlib.RandomBytes(16)
	mackey:=userlib.RandomBytes(16)
	content = MsgToEncrypt(symmetrickey, content)
	mac, err := MsgToMac(mackey, content)
	if err != nil {
		return uuid.New(), err
	}
	content, err = json.Marshal(mac)
	if err != nil {
		return uuid.New(), err
	}

	//Get recipient publickey
	toUUID, err := GetUserPublicUUID(to)
	if err != nil {
		return uuid.New(), err
	}
	pk, ok := userlib.KeystoreGet(toUUID)
	if !ok {
		return uuid.New(), errors.New("No valid PublicKey")
	}

	//public key encrypt mac and symmetric
	mackey, err = userlib.PKEEnc(pk, mackey)
	if err != nil {
		return uuid.New(), err
	}
	symmetrickey, err = userlib.PKEEnc(pk, symmetrickey)
	if err != nil {
		return uuid.New(), err
	}
	//init iwrapper
	var iwrapper InvitationWrapper
	iwrapper.Invitation = content
	iwrapper.MacKey = mackey
	iwrapper.SymmetricKey = symmetrickey
	iwrapperbytes,err := json.Marshal(iwrapper)
	if err != nil {
		return uuid.New(), err
	}
	inviteUUID:= uuid.New()
	if err != nil {
		return uuid.New(), err
	}
	userlib.DatastoreSet(inviteUUID, iwrapperbytes)
	return inviteUUID, nil
}//done
func CheckRemoteInvitation(userdata *User, from string, filename string) (invitation Invitation, err error) {
	inviteUUID, err:= GetInvitationUUID(userdata.UserName, filename, from)
	if err != nil {
		return invitation, err
	}
	content, ok:=userlib.DatastoreGet(inviteUUID)
	if !ok {
		return invitation, errors.New("Can't Get Invite")
	}
	var iwrapper InvitationWrapper
	err = json.Unmarshal(content, &iwrapper)
	if err != nil {
		return invitation, err
	}
	mackey := iwrapper.MacKey
	symmetrickey := iwrapper.SymmetricKey
	mackey, err = userlib.PKEDec(userdata.PrivateKey, mackey)
	if err != nil {
		return invitation, err
	}
	symmetrickey, err = userlib.PKEDec(userdata.PrivateKey, symmetrickey)
	if err != nil {
		return invitation, err
	}
	content = iwrapper.Invitation

	var mac Mac
	err = json.Unmarshal(content, &mac)
	if err != nil {
		return invitation, err
	}
	content = mac.Msg
	content = DecryptToMsg(symmetrickey, content)
	var sign Signature
	err = json.Unmarshal(content, &sign)
	if err != nil {
		return invitation, err
	}
	var verifyKey userlib.DSVerifyKey
	verifyID, err := GetUserSignUUID(from)
	if err != nil {
		return invitation, err
	}
	verifyKey, ok = userlib.KeystoreGet(verifyID)
	if !ok {
		return invitation, errors.New("No Verify Key!")
	}
	content, err = SignToMsg(verifyKey, sign)
	if err != nil {
		return invitation, err
	}
	err = json.Unmarshal(content, &invitation)
	if err != nil {
		return invitation, err
	}
	return invitation, nil
}//done

//==========================<FileMeta>========================
func SecureFileMeta(filemetameta Filemetameta, userdata *User, filemeta Filemeta)(output []byte, err error){
	output, err = json.Marshal(filemeta)
	if err != nil {
		return output, err
	}
	var sign Signature
	sign, err = MsgToSign(userdata.SignKey, output)
	if err != nil {
		return output, err
	}
	output, err = json.Marshal(sign)
	if err != nil {
		return output, err
	}
	output = MsgToEncrypt(filemetameta.SymmetricKey, output)
	macStruct, err := MsgToMac(filemetameta.MacKey, output)
	if err != nil {
		return output, err
	}
	output, err = json.Marshal(macStruct)
	if err != nil {
		return output, err
	}
	return output, nil
}//done
func CheckFileMeta(invitation Invitation, input []byte)(filemeta Filemeta, err error){
	output := input
	var mac Mac
	err = json.Unmarshal(output, &mac)
	if err != nil {
		return filemeta, err
	}
	output = mac.Msg
	output = DecryptToMsg(invitation.SymmetricKey, output)
	var sign Signature
	err = json.Unmarshal(output, &sign)
	if err != nil {
		return filemeta, err
	}
	var verifyKey userlib.DSVerifyKey
	verifyID, err := GetUserSignUUID(invitation.Owner)
	if err != nil {
		return filemeta, err
	}
	verifyKey, ok := userlib.KeystoreGet(verifyID)
	if !ok {
		return filemeta, errors.New("No Verify Key!")
	}
	output, err = SignToMsg(verifyKey, sign)
	if err != nil {
		return filemeta, err
	}
	err = json.Unmarshal(output, &filemeta)
	if err != nil {
		return filemeta, err
	}
	return filemeta, nil
}//done
func ReadRemoteFileMeta(invitation Invitation, userdata *User)(filemeta Filemeta, err error){
	filemetaUUID, err := GetFileMetaUUID(invitation.Owner, invitation.Name, invitation.Initial)
	if err != nil {
		return filemeta, err 
	}
	filemetabytes, ok := userlib.DatastoreGet(filemetaUUID)
	if !ok {
		return filemeta, errors.New("Cannot get Data for FileMetaBytes")
	}
	filemeta, err = CheckFileMeta(invitation, filemetabytes)
	if err != nil {
		return filemeta, err
	}
	return filemeta, nil
}//done
func UpdateRemoteFileMeta(filemetameta Filemetameta, userdata *User, filemeta Filemeta)(err error){

	filemetaUUID, err := GetFileMetaUUID(filemeta.Owner, filemeta.Name, filemetameta.Sent)

	if err != nil {
		return err 
	}
	filemetabytes, err := SecureFileMeta(filemetameta, userdata, filemeta)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(filemetaUUID, filemetabytes)
	return nil
}//done
func GenFileMeta(owner string, filename string)(filemeta Filemeta, err error){
	filemeta.SymmetricKey = userlib.RandomBytes(16)
	filemeta.MacKey = userlib.RandomBytes(16)
	sk, vk, err := userlib.DSKeyGen()
	if err!=nil {
		return filemeta, err
	}
	filemeta.SignKey = sk
	filemeta.VerifyKey = vk
	filemeta.Name = filename
	filemeta.Owner = owner
	return filemeta, nil
}//done

//===========================<Next Parts>=====================
func GetNextPartNum(filemeta Filemeta) (np int, err error){
	nextpartUUID, err := GetNextPartUUID(filemeta.Owner, filemeta.Name)
	if err != nil {
		return 0, err 
	}
	nextpartbytes, ok := userlib.DatastoreGet(nextpartUUID)
	if !ok {
		return 0, err
	}
	nextpartbytes, err = CheckFileNode(filemeta, nextpartbytes)
	if err != nil {
		return 0, err
	}
	var nextpart Nextpart
	err = json.Unmarshal(nextpartbytes, &nextpart)
	if err != nil {
		return 0, err
	}
	return nextpart.NextPart, nil
}//done
func UpdateNextPartNum(filemeta Filemeta, np int)(err error){
	nextpartUUID, err := GetNextPartUUID(filemeta.Owner, filemeta.Name)
	if err != nil {
		return err 
	}
	var nextpart Nextpart
	nextpart.NextPart = np
	nextpartbytes, err := json.Marshal(nextpart)
	if err != nil {
		return err 
	}
	nextpartbytes, err = SecureFileNode(filemeta, nextpartbytes)
	if err != nil {
		return err 
	}
	userlib.DatastoreSet(nextpartUUID, nextpartbytes)
	
	return nil
}//done

//==================<Files>=====================

func SearchFileInfo(userdata *User, file string) (fileinfo *Fileinfo, ok bool){
	for i := 0; i < userdata.NextFileInfo; i++ {
		fileinfo = &userdata.FileInfo[i]
		if(fileinfo.Name == file){ //file matches search
			return fileinfo, true
		}
	}
	return fileinfo, false
}//done
func SearchFileMetaMeta(userdata *User, fileinfo *Fileinfo, sent string) (fmm *Filemetameta, ok bool){
	var filemetameta *Filemetameta
	
	fmt.Println(2)
	fmt.Println(sent)
	fmt.Println(fileinfo.NextFileMetaMeta)
	for i := 0; i < fileinfo.NextFileMetaMeta; i++ {
		filemetameta = &fileinfo.FileMetaMeta[i]
		fmt.Println("loop", filemetameta.Sent)
		if(filemetameta.Sent == sent){ //sent matches the sent we are looking for
			fmt.Println(3)
			return filemetameta, true
		}
	}
	return filemetameta, false
}//done
func SecureFileNode(filemeta Filemeta, input []byte)(output []byte, err error){
	output = input
	var sign Signature
	sign, err = MsgToSign(filemeta.SignKey, output)

	if err != nil {
		return output, err
	}

	output, err = json.Marshal(sign)
	if err != nil {
		return output, err
	}

	output = MsgToEncrypt(filemeta.SymmetricKey, output)
	macStruct, err := MsgToMac(filemeta.MacKey, output)
	if err != nil {
		return output, err
	}

	output, err = json.Marshal(macStruct)
	if err != nil {
		return output, err
	}

	return output, nil
}//done
func CheckFileNode(filemeta Filemeta, input []byte)(output []byte, err error){
	output = input
	var mac Mac
	err = json.Unmarshal(output, &mac)
	if err != nil {
		return []byte(""), err
	}
	output = mac.Msg
	output = DecryptToMsg(filemeta.SymmetricKey, output)
	var sign Signature
	err = json.Unmarshal(output, &sign)
	if err != nil {
		return output, err
	}
	var verifyKey userlib.DSVerifyKey
	verifyKey = filemeta.VerifyKey
	output, err = SignToMsg(verifyKey, sign)
	if err != nil {
		return output, err
	}
	return output, nil
}//done
func ReadRemoteFileNode(filemeta Filemeta, filepart int)(output []byte, err error){
	fileUUID, err := GetFilePartUUID(filemeta.Owner, filemeta.Name, filepart)
	if err != nil {
		return []byte(""), err 
	}
	filenodebytes, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return []byte(""), err
	}
	filenodebytes, err = CheckFileNode(filemeta, filenodebytes)
	if err != nil {
		return []byte(""), err
	}
	return filenodebytes, nil
}//done
func ReadRemoteFile(filemeta Filemeta)(output []byte, err error){
	output = []byte{}
	nextpart, err := GetNextPartNum(filemeta)
	if err != nil {
		return []byte{}, err
	}
	filepart := []byte{}
	for i := 0; i < nextpart; i++ {
		filepart, err = ReadRemoteFileNode(filemeta, i)
		if err != nil {
			return []byte{}, err
		}
		output = append(output, filepart...)
	}
	return output, nil
}//done
func UpdateRemoteFile(filemeta Filemeta, input []byte, append bool)(err error){
	filepart:= 0
	if(append){
		filepart, err = GetNextPartNum(filemeta)
		if err != nil {
			return err
		}
	}

	fileUUID, err := GetFilePartUUID(filemeta.Owner, filemeta.Name, filepart)
	if err != nil {
		return err 
	}
	filebytes, err := SecureFileNode(filemeta, input)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileUUID, filebytes)
	if(append){
		return UpdateNextPartNum(filemeta, filepart+1)
	}else{
		return UpdateNextPartNum(filemeta, 1)
	}
	return nil
}//done





































//==================<User>======================
func UpdateLocalUser(userdata *User) (err error){
	userDataPtr, err := GetUser(userdata.UserName, userdata.password)
	if err != nil{
		return err
	}
	userdata.FileInfo = userDataPtr.FileInfo
	userdata.NextFileInfo = userDataPtr.NextFileInfo
	return nil
}
func UpdateRemoteUser(userdata *User) (err error){
	UUID, err := GetUserUUID(userdata.UserName, userdata.password)
	if err != nil {
		return err 
	}
	userbytes, err := SecureUser(userdata)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(UUID, userbytes)
	return nil
}
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
	userdata.password = password
	userdata.passHash = userlib.Hash([]byte(password))
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

