# NodeMCU Infra Red Blaster

This arduino code allow using nodeMCU as an IRBalster with TLS MQTT
The main idea is having an WIFI IR Blaster IOT device connecter to your own Broker with a good Security Level.
This is the first step to allow you using any Infra Red Device @home with IOT commande.

First you need edit the user_config.h with your MQTT broker and the fingerprint of your TLS certificate
const char*       broker      = ""; 
const char*       fingerprint = "";

After flashing, you should connect to the new Access point and finish the configuration.
WIFI and user configuration are store in the EEPROM.

You could subscribe to MQTT topic : "MCUMAC"/IR/get to get the IR signal from any device.

You could send to MQTT topic : "MCUMAC"/IR/send with JSON format as example:

<code>{"IR_RAW_DATA":"91-11-35-11-35-11-35-11-12-12-13-11-13-13-10-11-13-11-34-12-35-11-35-11-13-11-11-15-11-11-13-11-13-11-12-11-35-11-12-11-13-11-13-11-13-11-13-11-12-12-35-11-13-11-35-11-35-11-35-11-35-11-35-11-35-11-",
"IR_PROTOCOL":"SAMSUNG",
"IR_RAW_DATA_LENGTH":"68" , 
"HEXCODE" : "0xE0E040BF" }
</code>

The number in the nomal code divided by 50 to reduce the size of the message.
