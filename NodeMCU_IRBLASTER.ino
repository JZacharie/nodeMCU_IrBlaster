#include <IRremoteESP8266.h>// https://github.com/markszabo/IRremoteESP8266
#include <ESP8266WiFi.h>    // https://github.com/esp8266/Arduino
#include <WiFiManager.h>    // https://github.com/tzapu/WiFiManager
#include <PubSubClient.h>   // https://github.com/knolleary/pubsubclient/releases/tag/v2.6
#include <ArduinoJson.h>    // https://github.com/bblanchon/ArduinoJson
#include <Ticker.h>
#include <EEPROM.h>
#include "user_config.h"
#include "NodeMCU_IRBLASTER_Func.h"

void callback(char* p_topic, byte* p_payload, unsigned int p_length) {
  int i = 0;
  unsigned long IRcode;
  char message_buff[MQTT_MAX_PACKET_SIZE];
    
  // if recieved a correct topic message.
  if (String(MQTT_SEND_IR).equals(p_topic)) {
    
    for(i=0; i<p_length; i++) { message_buff[i] = p_payload[i]; }
    message_buff[i] = '\0';

    //Convert Payload to JSON Object
    StaticJsonBuffer<1000> jsonBuffer; 
    JsonObject& root = jsonBuffer.parseObject(message_buff);
        
    if (!root.success())  {
      Serial.println("parseObject() failed");
      DEBUG_PRINTLN(message_buff);  
    }else{
      String CHAR_IR_RAW_DATA           = root["IR_DATA"].as<String>();
      String CHAR_IR_PROTOCOL           = root["IR_P"].as<String>();
      String CHAR_IR_RAW_DATA_LENGTH    = root["IR_L"].as<String>();
      String STR_HEXCODE                = root["IR_HEX"].as<String>();
      int index=0;
      int secondindex=0;
      for(i=1; i<CHAR_IR_RAW_DATA_LENGTH.toInt(); i++) { //nombre d'element dans le tableau initial
          secondindex=CHAR_IR_RAW_DATA.indexOf("-",index);
          String temp=CHAR_IR_RAW_DATA.substring(index,secondindex);
          index=secondindex+1;
          IR_RAW_DATA[i-1]=temp.toInt()*USECPERTICK;
      }

      if (CHAR_IR_PROTOCOL=="UNKNOWN" || CHAR_IR_PROTOCOL=="SHARP" ||CHAR_IR_PROTOCOL=="JVC" ||CHAR_IR_PROTOCOL=="SANYO" ||CHAR_IR_PROTOCOL=="MITSUBISHI" ||CHAR_IR_PROTOCOL=="LG" ||CHAR_IR_PROTOCOL=="PANASONIC") {
         DEBUG_PRINTLN("USE RAW DATA to send");  
         irsend.sendRaw (IR_RAW_DATA,CHAR_IR_RAW_DATA_LENGTH.toInt(),38);
      }else{
         DEBUG_PRINTLN("Will try to USE HEXCODE to send "); 
         if (STR_HEXCODE.substring(0,2) == "0x"){ 
             STR_HEXCODE=STR_HEXCODE.substring(2); 
         }
         char CHAR_HEXCODE[10];
         STR_HEXCODE.toCharArray(CHAR_HEXCODE,10);
         uli_HEXCODE = strtoul(CHAR_HEXCODE,NULL,16);
         
         sendIRfromHEX(CHAR_IR_PROTOCOL);
      }
      //delay(10);
    }
  }
}

void PublishIR(char MQTT_PAYLOAD[400]) {
    if (mqttClient.publish(MQTT_RECEIVED_IR, MQTT_PAYLOAD, true)) {
      DEBUG_PRINTLN(F("INFO: MQTT message publish succeeded."));
    } else {
      DEBUG_PRINTLN(F("ERROR: MQTT message publish failed, either connection lost, or message too large"));
    }
}

void reconnect() {
  while (!mqttClient.connected()) {
    if (mqttClient.connect(MQTT_CLIENT_ID, settings.mqttUser, settings.mqttPassword)) {
      DEBUG_PRINTLN(F("INFO: The client is successfully connected to the MQTT broker"));
    } else {
      DEBUG_PRINTLN(F("ERROR: The connection to the MQTT broker failed"));
      //delay(60);
    }
  }

  if (mqttClient.subscribe(MQTT_SEND_IR)) {
     DEBUG_PRINT(F("INFO: Sending the MQTT subscribe succeeded. Topic: "));
     DEBUG_PRINTLN(MQTT_SEND_IR);
  } else {
     DEBUG_PRINT(F("ERROR: Sending the MQTT subscribe failed. Topic: "));
     DEBUG_PRINTLN(MQTT_SEND_IR);
  }
}

void setup() {
  Serial.begin(115200);
  irsend.begin();
  irrecv.enableIRIn(); // Start the receiver

  // Create the MQTT TOPIC 
  sprintf(MQTT_CLIENT_ID, "%06X", ESP.getChipId());           // get the Chip ID of the switch and use it as the MQTT client ID
  DEBUG_PRINT(F("INFO: MQTT client ID/Hostname: "));  DEBUG_PRINTLN(MQTT_CLIENT_ID);
  sprintf(MQTT_SEND_IR, "%06X/IR/send", ESP.getChipId());     // set the state topic: <Chip ID>/IR/send
  DEBUG_PRINT(F("INFO: MQTT send topic: "));          DEBUG_PRINTLN(MQTT_SEND_IR);
  sprintf(MQTT_RECEIVED_IR, "%06X/IR/get", ESP.getChipId());  // set the command topic: <Chip ID>/IR/get
  DEBUG_PRINT(F("INFO: MQTT recieved topic: "));      DEBUG_PRINTLN(MQTT_RECEIVED_IR);

  // load custom params from EEPROM
  EEPROM.begin(512);
  EEPROM.get(0, settings);
  EEPROM.end();

  //Configure the WIFI and MQTT
  WiFiManagerParameter custom_text("<p>MQTT username, password and broker port</p>");
  WiFiManagerParameter custom_mqtt_server("mqtt-server", "MQTT Broker IP", broker, STRUCT_CHAR_ARRAY_SIZE, "disabled");
  WiFiManagerParameter custom_mqtt_user("mqtt-user", "MQTT User",                  settings.mqttUser, STRUCT_CHAR_ARRAY_SIZE);
  WiFiManagerParameter custom_mqtt_password("mqtt-password", "MQTT Password", settings.mqttPassword, STRUCT_CHAR_ARRAY_SIZE, "type = \"password\"");
  WiFiManagerParameter custom_mqtt_port("mqtt-port", "MQTT Broker Port", settings.mqttPort, 6);

  WiFiManager wifiManager;

  wifiManager.addParameter(&custom_text);
  wifiManager.addParameter(&custom_mqtt_user);
  wifiManager.addParameter(&custom_mqtt_password);
  wifiManager.addParameter(&custom_mqtt_server);
  wifiManager.addParameter(&custom_mqtt_port);
  wifiManager.setAPCallback(configModeCallback);
  wifiManager.setConfigPortalTimeout(180);

  // set config save notify callback
  wifiManager.setSaveConfigCallback(saveConfigCallback);

  if (!wifiManager.autoConnect(MQTT_CLIENT_ID)) {
    //ESP.reset();
    //delay(10);
  }

  if (shouldSaveConfig) {
    strcpy(settings.mqttServer,   broker);
    strcpy(settings.mqttUser,     custom_mqtt_user.getValue());
    strcpy(settings.mqttPassword, custom_mqtt_password.getValue());
    strcpy(settings.mqttPort,     custom_mqtt_port.getValue());
    EEPROM.begin(512);
    EEPROM.put(0, settings);
    EEPROM.end();
  }

  verifyFingerprint();                                                    // check the fingerprint of SSL cert
  mqttClient.setServer(settings.mqttServer, atoi(settings.mqttPort));     // configure MQTT
  mqttClient.setCallback(callback);
  reconnect();                                                            // connect to the MQTT broker
  ticker.detach();
}

void loop() {
  yield();
  // keep the MQTT client connected to the broker
  if (!mqttClient.connected()) {
    reconnect();
  }
  mqttClient.loop();
 
  decode_results  results;        // Somewhere to store the results
  if (irrecv.decode(&results)) {
    
    String IR_GET_RAW_DATA="";
    for (int i = 1; i < results.rawlen; i++) { 
       IR_GET_RAW_DATA+=String(results.rawbuf[i])+"-";
    }
    
    sprintf(CHAR_GET_IR_HEXCODE,"0x%X",results.value); // Prepare for MQTT
    IR_GET_HEXCODE=String(CHAR_GET_IR_HEXCODE);

    switch (results.decode_type) {
        default:
        case UNKNOWN:      CHAR_GET_IR_PROTOCOL="UNKNOWN";       break ;
        case NEC:          CHAR_GET_IR_PROTOCOL="NEC";           break ;
        case SONY:         CHAR_GET_IR_PROTOCOL="SONY";          break ;
        case RC5:          CHAR_GET_IR_PROTOCOL="RC5";           break ;
        case RC6:          CHAR_GET_IR_PROTOCOL="RC6";           break ;
        case DISH:         CHAR_GET_IR_PROTOCOL="DISH";          break ;
        case SHARP:        CHAR_GET_IR_PROTOCOL="SHARP";         break ;
        case JVC:          CHAR_GET_IR_PROTOCOL="JVC";           break ;
        case SANYO:        CHAR_GET_IR_PROTOCOL="SANYO";         break ;
        case MITSUBISHI:   CHAR_GET_IR_PROTOCOL="MITSUBISHI";    break ;
        case SAMSUNG:      CHAR_GET_IR_PROTOCOL="SAMSUNG";       break ;
        case LG:           CHAR_GET_IR_PROTOCOL="LG";            break ;
        case WHYNTER:      CHAR_GET_IR_PROTOCOL="WHYNTER";       break ;
        case PANASONIC:    CHAR_GET_IR_PROTOCOL="PANASONIC";     break ;
    }
    char MQTT_PAYLOAD[400] = {0};
    int IR_GET_RAW_DATA_LENGTH=results.rawlen+1;
    String IR_GET_PROTOCOL=String(CHAR_GET_IR_PROTOCOL);
    String JSONRAWDATA="{\"IR_DATA\":\""+ IR_GET_RAW_DATA +"\",\"IR_P\":\""+ IR_GET_PROTOCOL +"\",\"IR_L\":\""+ IR_GET_RAW_DATA_LENGTH +"\" ,\"IR_HEX\":\""+ IR_GET_HEXCODE +"\" }";
    JSONRAWDATA.toCharArray   (MQTT_PAYLOAD,   400);
    PublishIR(MQTT_PAYLOAD);
    
    //delay(100); 
    irrecv.resume();                            // Receive the next value
  }
  //delay(100);
  yield();
}
