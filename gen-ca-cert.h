// Copyright 2020 zelbrium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __GEN_CA_CERT_H__
#define __GEN_CA_CERT_H__

#include <stdint.h>
#include <stddef.h>

/**
 * @function cacert_from_priv_key_DER
 *
 * @abstract
 * Generates a Certificate Authority root (self-signed) certificate from a private key.
 *
 * @discussion
 * The generated certificate uses a large, random serial number and has
 * appropriate configuration (keyUsage, etc.) for usage as a CA.
 *
 * @param rsaPrivKeyDER
 * The private key in PKCS1 DER encoding. This is the format of data returned
 * by Apple Security Framework function SecKeyCopyExternalRepresentation().
 *
 * @param rsaPrivKeyDERLen
 * Length in bytes of rsaPrivKeyDER.
 *
 * @param commonName
 * (Required) NULL-terminated UTF8 string containing the name of the
 * Certificate Authority. This is also used for the Subject Alt Name field.
 *
 * @param organization
 * (Required) NULL-terminated UTF8 string containing the CA's organization.
 *
 * @param countryCode
 * (Required) NULL-terminated UTF8 string containing the CA's location country
 * code. For example, "US".
 *
 * @param hoursBefore
 * Number of hours before the current time that the cert is valid. Before this
 * time, the cert is expired.
 *
 * @param hoursAfter
 * Number of hours after the current time that the cert is valid. After this
 * time, the cert is expired.
 *
 * @param certDEROut
 * (Required) Output location for the X509 v3 DER-encoded certificate This
 * could be base64 encoded and written to a PEM file. Free this with free(3).
 *
 * @param certDERLenOut
 * (Required) Output location for the length in bytes of certDEROut.
 *
 * @param errStrOut
 * (Optional) Output location for an error string. May contain multiple lines.
 * Outputs NULL if no error occurred or if the error string failed to generate.
 * Free this with free(3).
 *
 * @result
 * 1 on success, 0 on failure. On failure, errStrOut may be filled with an
 * error message.
 */
int cacert_from_priv_key_DER(
	uint8_t *rsaPrivKeyDER,
	size_t rsaPrivKeyDERLen,
	const char *commonName,
	const char *organization,
	const char *countryCode,
	int hoursBefore,
	int hoursAfter,
	uint8_t **certDEROut,
	size_t *certDERLenOut,
	char **errStrOut);

#endif // __GEN_CA_CERT_H__
