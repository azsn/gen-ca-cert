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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "gen-ca-cert.h"

int main(int argc, char **argv)
{
	unsigned char *buf = malloc(10000);
	ssize_t len = read(STDIN_FILENO, buf, 10000);
	if (len <= 0) {
		fprintf(stderr, "No key read\n");
		return 1;
	}

	uint8_t *certDER = NULL;
	size_t certDERLen = 0;
	char *errStr = NULL;

	int ret = cacert_from_priv_key_DER(
		buf,
		len,
		"Gen CA Demo",
		"Gen CA Org",
		"US",
		1, // valid since 1 hour before now
		10, // valid until 10 hours after now
		&certDER,
		&certDERLen,
		&errStr
	);

	free(buf);

	if (!ret) {
		fprintf(stderr, "Failed to generate certificate:\n%s\n", errStr);
		free(errStr);
		return 1;
	}

	// Use -binout flag then pipe the output into 'base64 --break=64' to
	// get the base64 part of a PEM file.
	if (argc > 1 && strcmp(argv[1], "-binout") == 0) {
		fwrite(certDER, 1, certDERLen, stdout);
	} else {
		for (size_t i = 0; i < certDERLen; i += 1) {
			if (i > 0) {
				printf(":");
			}
			printf("%02X", certDER[i]);
		}
		printf("\n");
	}

	free(certDER);

	return 0;
}
