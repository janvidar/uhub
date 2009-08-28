/**
 * A remote uhub admin client.
 */


#include "uhub.h"
#include "adcclient.h"
#include "network/connection.h"

int main(int argc, char** argv)
{
	struct ADC_client client;
	net_initialize();

	ADC_client_create(&client, "uhub-admin", "stresstester");
	ADC_client_connect(&client, "adc://adc.extatic.org:1511");

	event_dispatch();

	ADC_client_destroy(&client);
	net_destroy();
	return 0;
}


