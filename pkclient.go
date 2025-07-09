package pkclient

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"golang.org/x/term"
)

const (
	CURVE25519_OID_RAW  = "06032B656E"  // 1.3.101.110 ("id-X25519")
	NoisePrivateKeySize = 32
	NoisePublicKeySize  = 32
)

type DeriveKeyPair struct {
    publicKey  p11.Object
    privateKey p11.Object
}

type PKClient struct {
	HSM_Session struct {
		slot       uint        // slot to use on the HSM
		key_label  string      // label of derivation key. Unused
		key_id     uint        // ID of the key on the device
		session    p11.Session // session object
		loggedIn   bool        // to track the session login status
		privKeyObj p11.Object  // the private key handle key on the hsm
		pubKeyObj  p11.Object  // the public key handle on the hsm
		module     p11.Module
	}
}

// Try to open a session with the HSM, select the slot and login to it
// A public and private key must already exist on the hsm
// The private and match public key must also be found during setup
// The private key must be the Curve25519 Algorithm, OID 1.3.101.110
//
func New(hsmPath string, slot uint, pin string) (*PKClient, error) {
	client := new(PKClient)
	module, err := p11.OpenModule(hsmPath)
	if err != nil {
		err := fmt.Errorf("failed to load module library: %s", hsmPath)
		return nil, err
	}
	client.HSM_Session.module = module // save so we can close

	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}
	// try to open a session on the slot
	client.HSM_Session.session, err = slots[slot].OpenWriteSession()
	if err != nil {
		err := fmt.Errorf("failed to open session on slot %d", slot)
		return nil, err
	}
	client.HSM_Session.slot = slot

	// try to login to the slot

	if pin == "ask" {
		retries := 0
		for retries < 2 {
			fmt.Printf("Enter Pin for slot %d:\n", slot)
			userPin, _ := term.ReadPassword(0) // no echo
			pin := strings.TrimSpace(string(userPin))
			err = client.HSM_Session.session.Login(pin)
			if err != nil {
				fmt.Println("Login unsuccessful")
			} else {
				pin = "-1" // don't save the pin
				break
			}
			retries++
		}
	} else {
		err = client.HSM_Session.session.Login(pin)
		if err != nil {
			err = fmt.Errorf("unable to login. error: %w", err)
			return nil, err
		}
	}
	// login successful
	client.HSM_Session.loggedIn = true

	// make sure the hsm has a curve25519 key for deriving
	X25519KeyPair, err := client.findDeriveKey()
	if err != nil {
		err = fmt.Errorf("failed to find X25519 key for deriving: %w", err)
		return nil, err
	}

	client.HSM_Session.pubKeyObj = X25519KeyPair.publicKey
	client.HSM_Session.privKeyObj = X25519KeyPair.privateKey

	return client, nil
}

// alternate constructor that will not save the hsm pin and prompt
// the user for the pin number
func New_AskPin(hsmPath string, slot uint) (*PKClient, error) {
	client, err := New(hsmPath, slot, "ask")
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Callers should use this when closing to clean-up properly and logout
func (client *PKClient) Close() {
	client.HSM_Session.session.Logout()
	client.HSM_Session.session.Close()
	client.HSM_Session.module.Destroy()
}

// Returns a 32 byte length key from the hsm. attempts to convert to a usable WG key
func (client *PKClient) PublicKeyNoise() (key [NoisePublicKeySize]byte, err error) {
	if !client.HSM_Session.loggedIn {
		return [NoisePublicKeySize]byte{}, fmt.Errorf("error: must login to hsm first")
	}

	// From my understanding, for X25519 the public key is not stored
	// in `CKA_VALUE` but instead in attribute `CKA_EC_POINT`.
	srcKey, err := client.HSM_Session.pubKeyObj.Attribute(pkcs11.CKA_EC_POINT);
	if err != nil {
		return [NoisePublicKeySize]byte{}, err
	}
	if len(srcKey) < NoisePublicKeySize {
		return [NoisePublicKeySize]byte{}, fmt.Errorf("Key of wrong size returned (%d)", len(srcKey))
	}

	// On a Nitrokey Start, this gets the full EC_POINT value of 34 bytes instead of 32,
	// This returns the last 32 bytes.  TODO: check the discarded prefix.
	if len(srcKey) == NoisePublicKeySize + 2 {
		// fmt.Printf("DEBUG: Discarding prefix of key\n")
		srcKey = srcKey[2:]
	}

	copy(key[:], srcKey[:])
	return key, nil
}

// derive a shared secret using the input public key against the private key that was found during setup
// returns a fixed 32 byte array
func (client *PKClient) DeriveNoise(peerPubKey [NoisePublicKeySize]byte) (secret [NoisePrivateKeySize]byte, err error) {
	if !client.HSM_Session.loggedIn {
		err := fmt.Errorf("error: must login to hsm first")
		var zkey [NoisePublicKeySize]byte // temp garbage key so we can return the error
		return zkey, err
	}

	var mech_mech uint = pkcs11.CKM_ECDH1_DERIVE

	// before we call derive, we need to have an array of attributes which specify the type of
	// key to be returned, in our case, it's the shared secret key, produced via deriving
	// This template pulled from OpenSC pkcs11-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	// setup the parameters which include the peer's public key
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey[:NoisePublicKeySize])

	var mech *pkcs11.Mechanism = pkcs11.NewMechanism(mech_mech, ecdhParams)

	// derive the secret key from the public key as input and the private key on the device
	tmpKey, err := p11.PrivateKey(client.HSM_Session.privKeyObj).Derive(*mech, attrTemplate)
	if err != nil {
		return secret, err
	}

	copy(secret[:], tmpKey[:NoisePrivateKeySize])
	return secret, err
}

// Try to find a suitable key on the hsm for x25519 key derivation
func (dev *PKClient) findDeriveKey() (keys DeriveKeyPair, err error) {
	//  EC_PARAMS value: the specifc OID for x25519 operation
	rawOID, _ := hex.DecodeString(CURVE25519_OID_RAW)
	keys = DeriveKeyPair{}

	privateAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	// FindObject expects a single key with above attrs, otherwise it returns err
	keys.privateKey, err = dev.HSM_Session.session.FindObject(privateAttrs)
	if err != nil {
		return keys, fmt.Errorf("Could not find private key with attrs: %w", err)
	}

	CkaId, err := keys.privateKey.Attribute(pkcs11.CKA_ID);
	if err != nil {
		return keys, fmt.Errorf("Could not find CKA_ID of private key: %w", err)
	}

	publicAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, CkaId),
	}

	keys.publicKey, err = dev.HSM_Session.session.FindObject(publicAttrs)
	if err != nil {
		return keys, fmt.Errorf("Could not find public key: %w", err)
	}

	return keys, nil
}
