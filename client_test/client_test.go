package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, "")
			alice.StoreFile(aliceFile, []byte(""))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
	Describe("Self Test1", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Getting user Alice.")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

	})
	Describe("Self Test2", func() {

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
	
	Describe("Self Test3", func() {

		Specify("Duplicate", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Initializing user Alice, again.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

	})
	Describe("Self Test4", func() {

		Specify("Empty Name", func() {
			userlib.DebugMsg("Initializing empty username")
			_, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

	})
	Describe("Self Test5", func() {

		Specify("GetUser", func() {
			userlib.DebugMsg("Getting user Alice without initializing.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())


			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Assuming Alice's Identity.")
			aliceLaptop, err = client.GetUser("alice", "SuperEasyPassword")
			Expect(err).ToNot(BeNil())

			// userlib.DebugMsg("Tampering with the user storage.")
			// clientUUID, _:= uuid.FromBytes(userlib.Hash(userlib.Hash([]byte("alice" + defaultPassword)))[:16])
			// content, _ := userlib.DatastoreGet(clientUUID)
			// userlib.DatastoreSet(clientUUID, content[1:])
			// aliceLaptop, err = client.GetUser("alice", defaultPassword)
			// Expect(err).ToNot(BeNil())
			
		})

	})
	Describe("Self Test6", func() {

		Specify("FileStorage", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			// Different users can store files using the same filename, because each user must have a separate personal file namespace.
			// Overwriting the contents of a file does not change who the file is shared with.
			// Users can have multiple active user sessions at once.
			userlib.DebugMsg("Alice,Bob,Charles storing file %s with content: %s %s %s", aliceFile, contentOne, contentTwo, contentThree)
			alice.StoreFile(aliceFile, []byte(contentOne))
			bob.StoreFile(aliceFile, []byte(contentTwo))
			charles.StoreFile(aliceFile, []byte(contentThree))

			userlib.DebugMsg("Checking that Alice,Bob,Charles can all still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			data, err = charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())


			
		})

	})
	Describe("Self Test7", func() {

		Specify("LoadFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accessing a file without storing it.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			
		})

	})
	Describe("Self Test8", func() {

		Specify("AppendToFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accessing a file without storing it.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			
		})

	})
	Describe("Self Test9", func() {

		Specify("AppendToFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accessing a file without storing it.")
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
			
			userlib.DebugMsg("Store AliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing contentOne into aliceFile.")
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending an emtpy string onto contentOne")
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne+contentOne)))

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob Stores AliceFile.")
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Invite Bob to edit bobFile. (fails)")
			_, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Invite ADINSX to edit bobFile. (fails)")
			_, err = alice.CreateInvitation(aliceFile, "ADINSX")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Invite Bob to edit aliceFile.")
			invitationid, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob Accepts aliceFile from Alice rename BobFile.")
			err = bob.AcceptInvitation("alice", invitationid, bobFile)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Bob Stores to BobFile.")
			err = bob.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())


			userlib.DebugMsg("Bob Creates AliceFile.")
			err = bob.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("ReInitializing user Charles. (failed)")
			_, err = client.InitUser("charles", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Invite Random to edit aliceFile. (failed)")
			_, err = alice.CreateInvitation(aliceFile, "ow98jiewhnwodifwoid")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Invite Empty to edit aliceFile. (failed)")
			_, err = alice.CreateInvitation(aliceFile, "")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Invite Charles to edit RandomFile. (failed)")
			_, err = alice.CreateInvitation("ow98jiewhnwodifwoid", "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Invite Charles to edit EmptyFileName. (failed)")
			_, err = alice.CreateInvitation("", "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Invite Charles to edit aliceFile.")
			invitationid, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user doris.")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Doris Accepts aliceFile from Alice (fails)")
			err = doris.AcceptInvitation("alice", invitationid, bobFile)
			Expect(err).ToNot(BeNil())


			userlib.DebugMsg("Doris Creates AliceFile.")
			err = doris.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())


			userlib.DebugMsg("Doris Invite Charles to edit aliceFile.")
			rejectid, err := doris.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles Accepts DorisInvitation (from Alice) rename BobFile. (fails)")
			err = charles.AcceptInvitation("alice", rejectid, bobFile)
			Expect(err).ToNot(BeNil())


			userlib.DebugMsg("Charles Accepts aliceFile from Alice rename BobFile.")
			err = charles.AcceptInvitation("alice", invitationid, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles Loads BobFile.")
			data, err = charles.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Alice Loads AliceFile.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Bob Loads BobFile.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Bob Loads AliceFile.")
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Bob Stores 2 to BobFile.")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles Stores 1 to BobFile.")
			err = charles.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Bob Invites Charles to edit aliceFile.")
			invitationid, err = bob.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles Accepts aliceFile from bob rename BobFile. (fail)")
			err = charles.AcceptInvitation("bob", invitationid, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles Accepts aliceFile from bob rename AliceFile.")
			err = charles.AcceptInvitation("bob", invitationid, aliceFile)
			Expect(err).To(BeNil())

			// userlib.DebugMsg("Charles append 1 to AliceFile.")
			// err = charles.AppendToFile(aliceFile, []byte(contentOne))
			// Expect(err).To(BeNil())

			userlib.DebugMsg("Charles Invites Dorris to edit bobFile.")
			invitationid, err = charles.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("doris Loads bobFile. (fail)")
			data, err = doris.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Doris Accepts bobFile from bob rename BobFile. (Fail)")
			err = doris.AcceptInvitation("bob", invitationid, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Doris Accepts bobFile from charles rename BobFile. ")
			err = doris.AcceptInvitation("charles", invitationid, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris Loads BobFile.")
			data, err = doris.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))


			userlib.DebugMsg("Charles Revoke BobFile From Doris (fail).")
			err = charles.RevokeAccess(bobFile, "doris")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Revoke AliceFile From Random (fail).")
			err = alice.RevokeAccess(aliceFile, "sodifjsdoifjs")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Revoke randomFile From Charles (fail).")
			err = alice.RevokeAccess("randomfilehere.txt", "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice Revoke randomFile From NoOne (fail).")
			err = alice.RevokeAccess(aliceFile, "")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob Loads BobFile. ")
			data, err = charles.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			
			userlib.DebugMsg("Alice Revoke randomFile From Charles.")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris Loads BobFile. (Fail)")
			_, err = doris.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())


			userlib.DebugMsg("Charles Loads BobFile. (Fail)")
			_, err = charles.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob Loads BobFile. ")
			data, err = charles.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			
		})

	})
	Describe("Self Test10", func() {

		Specify("AppendToFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			alice, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Invites Bob to edit aliceFile.")
			invitationid, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Revoke aliceFile From Bob.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())


			userlib.DebugMsg("bob tries accept Invitation. (failed)")
			err = bob.AcceptInvitation("alice", invitationid, bobFile)
			Expect(err).ToNot(BeNil())
			
		})

	})
})
