package main

import (
	"github.com/labstack/echo"
	"net/http"
)

var hardcodedSPIFFEMasks = _strValue{true, "spiffe://test1.domain/*"}

type _strValue struct {
	Locked bool
	Value  string
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

func fakePolicy(c echo.Context) error {
	r := serverPolicy{}
	r.Policy.SubjAltNameUriRegex = hardcodedSPIFFEMasks
	r.Policy.SubjAltNameUriAllowed = true
	return c.JSON(http.StatusOK, &r)
}
