package main

import (
	"encoding/json"
	"fmt"
	"github.com/labstack/echo"
	"io/ioutil"
	"net/http"
)

const (
	zoneFileTemplate = "faketpp/zones/%s.json"
)

type _strValue struct {
	Locked bool
	Value  string
}

type Zone struct {
	CACertPemFile string
	CAKeyPemFile  string
	PolicyFile    string
}

type serverPolicy struct {
	Policy struct {
		CertificateAuthority _strValue
		CsrGeneration        _strValue
		KeyGeneration        _strValue
		KeyPair              struct {
			KeyAlgorithm _strValue
			KeySize      struct {
				Locked bool
				Value  int
			}
			EllipticCurve struct {
				Locked bool
				Value  string
			}
		}
		ManagementType _strValue

		PrivateKeyReuseAllowed  bool
		SubjAltNameDnsAllowed   bool
		SubjAltNameEmailAllowed bool
		SubjAltNameIpAllowed    bool
		SubjAltNameUpnAllowed   bool
		SubjAltNameUriAllowed   bool
		SubjAltNameUriRegex     _strValue
		Subject                 struct {
			City               _strValue
			Country            _strValue
			Organization       _strValue
			OrganizationalUnit struct {
				Locked bool
				Values []string
			}

			State _strValue
		}
		UniqueSubjectEnforced bool
		WhitelistedDomains    []string
		WildcardsAllowed      bool
	}
	Error string
}

var currentPolicy serverPolicy

func fakePolicy(c echo.Context) error {
	r := currentPolicy
	return c.JSON(http.StatusOK, &r)
}

func parseZone(zoneDN string) (zone Zone, err error) {
	//removing `\\VED\\Policy\\`
	zoneDN = zoneDN[12:]
	b, err := ioutil.ReadFile(fmt.Sprintf(zoneFileTemplate, zoneDN))
	if err != nil {
		return
	}
	err = json.Unmarshal(b, &zone)
	if err != nil {
		return
	}
	return
}
