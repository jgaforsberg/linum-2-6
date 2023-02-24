/*
###	Baserat på kodskelett från Linux PAM ADG kapitel 8	###
###	1. Användaren ska tillåtas access som vanlig user	###
###	2. En användare ska ha full access utan lösenordskrav	###
###	3. Alla användare i en grupp ska ha full access utan	###
###	3. lösenordskrav, alla andra nekas			###
###	Konfigurationer bifogade i ../B1 & ../B2 & ../B3	###
###	Konfigurationer tillämpas i /etc/pam.d/checkuser	###
###	respektive /etc/security/checkuser.conf			###
###	Applikation med autentisering	 			###
###	jgaforsberg gufoo0047 gusfor-1 gufr22			###
*/

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
	misc_conv,
	NULL
};

int main(int argc, char *argv[])
{
	pam_handle_t *pamh = NULL;
	int retval;
	const char *user = "nobody";

	// kontrollera input med feedback till användare
	if(argc != 2) {
		fprintf(stderr, "Usage: checkuser [username]\n");
		exit(1);
	}
	// användarnamn ställs till argv[1]
	user = argv[1];
	// initierar PAM mot /etc/pam.d/checkuser
	retval = pam_start("checkuser", user, &conv, &pamh);
	// kontroll mot auth och acct
	if (retval == PAM_SUCCESS)
		retval = pam_authenticate(pamh, 0); // authentication - is user really user?
	if (retval == PAM_SUCCESS)
		retval = pam_acct_mgmt(pamh, 0); // authorization - can user do this?
	if (retval == PAM_SUCCESS)
		fprintf(stdout, "Auth success!\n");
	else
		fprintf(stdout, "Auth failure!\n");

	if (pam_end(pamh,retval) != PAM_SUCCESS) { // close Linux-PAM
		pamh = NULL;
		fprintf(stderr, "checkuser: failed to release authenticator\n");
		exit(1);
	}

	return ( retval == PAM_SUCCESS ? 0:1 ); // indicates success
}

