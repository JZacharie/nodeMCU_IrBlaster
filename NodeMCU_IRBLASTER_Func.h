IRsend irsend(SEND_PIN);
IRrecv irrecv(RECV_PIN);
decode_results results;
#define         DEBUG                       // enable debugging
#define         STRUCT_CHAR_ARRAY_SIZE 24   // size of the arrays for MQTT username, password, etc.
#define         DEBUG_PRINT(x)    Serial.print(x)
#define         DEBUG_PRINTLN(x)  Serial.println(x)

// MQTT
char              MQTT_CLIENT_ID[7]                                 = {0};
char              MQTT_RECEIVED_IR[STRUCT_CHAR_ARRAY_SIZE]          = {0};
char              MQTT_SEND_IR[STRUCT_CHAR_ARRAY_SIZE]              = {0};
char              MQTT_PAYLOAD[500]                                 = {0};

// IR Needs
int               bits;
String            decode_type;                                  // Protocol for IR analyse
String            CHAR_GET_IR_PROTOCOL;                         // Protocol From MQTT
unsigned int      IR_RAW_DATA[500]={0};                     // DataSet which contain RAWdata of IR
char              CHAR_GET_IR_HEXCODE[STRUCT_CHAR_ARRAY_SIZE]       = {0}; //HEXCODE
String            IR_GET_HEXCODE;
unsigned long     uli_HEXCODE;

StaticJsonBuffer<600> jsonBuffer; 

typedef struct { // Settings for MQTT
  char            mqttUser[STRUCT_CHAR_ARRAY_SIZE]                  = "";//{0};
  char            mqttPassword[STRUCT_CHAR_ARRAY_SIZE]              = "";//{0};
  char            mqttServer[STRUCT_CHAR_ARRAY_SIZE]                = "";//{0};
  char            mqttPort[6]                                       = "";//{0};
} Settings;

bool shouldSaveConfig = false; // flag for saving data
   
enum CMD {
  CMD_NOT_DEFINED,
  CMD_PIR_STATE_CHANGED,
  CMD_BUTTON_STATE_CHANGED,
};

volatile uint8_t cmd = CMD_NOT_DEFINED;

Settings          settings;
Ticker            ticker;
WiFiClientSecure  wifiClient;
PubSubClient      mqttClient(wifiClient);

void saveConfigCallback () { // callback notifying us of the need to save config
  shouldSaveConfig = true;
}

void configModeCallback (WiFiManager *myWiFiManager) {
}

void buttonStateChangedISR() {
  cmd = CMD_BUTTON_STATE_CHANGED;
}

unsigned long hex2int(char *a, unsigned int len){
   int i;
   unsigned long val = 0;

   for(i=0;i<len;i++)
      if(a[i] <= 57)
       val += (a[i]-48)*(1<<(4*(len-1-i)));
      else
       val += (a[i]-55)*(1<<(4*(len-1-i)));
   return val;
}

void  ircode (decode_results *results){
  // Panasonic has an Address
  if (results->decode_type == PANASONIC) {
    Serial.print(results->panasonicAddress, HEX);
    Serial.print(":");
  }

  // Print Code
  Serial.print(results->value, HEX);
}

void  encoding (decode_results *results){
  switch (results->decode_type) {
    default:
    case UNKNOWN:      Serial.print("UNKNOWN");       break ;
    case NEC:          Serial.print("NEC");           break ;
    case SONY:         Serial.print("SONY");          break ;
    case RC5:          Serial.print("RC5");           break ;
    case RC6:          Serial.print("RC6");           break ;
    case DISH:         Serial.print("DISH");          break ;
    case SHARP:        Serial.print("SHARP");         break ;
    case JVC:          Serial.print("JVC");           break ;
    case SANYO:        Serial.print("SANYO");         break ;
    case MITSUBISHI:   Serial.print("MITSUBISHI");    break ;
    case SAMSUNG:      Serial.print("SAMSUNG");       break ;
    case LG:           Serial.print("LG");            break ;
    case WHYNTER:      Serial.print("WHYNTER");       break ;
    case PANASONIC:    Serial.print("PANASONIC");     break ;
  }
}

void  dumpInfo (decode_results *results){
  // Show Encoding standard
  Serial.print("Encoding  : ");
  decode_type=String(results->decode_type);
  encoding(results);
  Serial.println("");

  // Show Code & length
  Serial.print("Code      : ");
  ircode(results);
  Serial.print(" (");
  Serial.print(results->bits, DEC);
  bits = results->bits;
  Serial.println(" bits)");
}

void  dumpRaw (decode_results *results){
  // Print Raw data
  Serial.print("Timing[");
  Serial.print(results->rawlen-1, DEC);
  Serial.println("]: ");

  for (int i = 1;  i < results->rawlen;  i++) {
    unsigned long  x = results->rawbuf[i] * USECPERTICK;
    if (!(i & 1)) {  // even
      Serial.print("-");
      if (x < 1000)  Serial.print(" ") ;
      if (x < 100)   Serial.print(" ") ;
      Serial.print(x, DEC);
    } else {  // odd
      Serial.print("     ");
      Serial.print("+");
      if (x < 1000)  Serial.print(" ") ;
      if (x < 100)   Serial.print(" ") ;
      Serial.print(x, DEC);
      if (i < results->rawlen-1) Serial.print(", "); //',' not needed for last one
    }
    if (!(i % 8))  Serial.println("");
  }
  Serial.println("");                    // Newline
}

void  dumpCode (decode_results *results){
  // Start declaration
  //RawData="";
  Serial.print("unsigned int  ");          // variable type
  Serial.print("rawData[");                // array name
  //RawData=RawData+"rawData[";
  Serial.print(results->rawlen - 1, DEC);  // array size
  //RawData=RawData+String(results->rawlen - 1);
  Serial.print("] = {");                   // Start declaration
  //RawData=RawData+"] = {";
  
  // Dump data
  for (int i = 0;  i < results->rawlen;  i++) {
    Serial.print(results->rawbuf[i] * USECPERTICK, DEC);
    //RawData=RawData+String(results->rawbuf[i] * USECPERTICK);
    if ( i < results->rawlen-1 ) {
      Serial.print(","); // ',' not needed on last one
      //RawData=RawData+",";
    }
    if (!(i & 1)) {
      Serial.print(" ");
      //RawData=RawData+" ";
    }
  }

  // End declaration
  Serial.print("};");  // 
  //RawData=RawData+"};";
  
  // Comment
  Serial.print("  // ");
  encoding(results);
  Serial.print(" ");
  ircode(results);

  // Newline
  Serial.println("");

  // Now dump "known" codes
  if (results->decode_type != UNKNOWN) {

    // Some protocols have an address
    if (results->decode_type == PANASONIC) {
      Serial.print("unsigned int  addr = 0x");
      Serial.print(results->panasonicAddress, HEX);
      Serial.println(";");
    }

    // All protocols have data
    Serial.print("unsigned int  data = 0x");
    Serial.print(results->value, HEX);
    Serial.println(";");
  }
}

void restart() {
  DEBUG_PRINTLN(F("INFO: Restart..."));
  ESP.reset();
  delay(10);
}

void reset() {
  DEBUG_PRINTLN(F("INFO: Reset..."));
  WiFi.disconnect();
  delay(10);
  ESP.reset();
  delay(10);
}

void verifyFingerprint() {
  DEBUG_PRINT(F("INFO: Connecting to "));
  DEBUG_PRINTLN(settings.mqttServer);

  if (!wifiClient.connect(settings.mqttServer, atoi(settings.mqttPort))) {
    DEBUG_PRINTLN(F("ERROR: Connection failed. Halting execution"));
    reset();
  }

  if (wifiClient.verify(fingerprint, settings.mqttServer)) {
    DEBUG_PRINTLN(F("INFO: Connection secure"));
  } else {
    DEBUG_PRINTLN(F("ERROR: Connection insecure! Halting execution"));
    reset();
  }
}

void sendIRfromHEX(String CHAR_IR_PROTOCOL){
  if (CHAR_IR_PROTOCOL=="DISH") {
     DEBUG_PRINTLN("DISH");  
     irsend.sendDISH(uli_HEXCODE, 32);
  }
  if (CHAR_IR_PROTOCOL=="NEC") {
     DEBUG_PRINTLN("NEC");  
     irsend.sendNEC(uli_HEXCODE, 32);
  }
  if (CHAR_IR_PROTOCOL=="RC5") {
     DEBUG_PRINTLN("RC5");  
     irsend.sendRC5(uli_HEXCODE, 32);
  }
  if (CHAR_IR_PROTOCOL=="RC6") {
     DEBUG_PRINTLN("RC6");  
     irsend.sendRC6(uli_HEXCODE, 32);
  }
  if (CHAR_IR_PROTOCOL=="SAMSUNG") {
     DEBUG_PRINTLN("SAMSUNG");  
     irsend.sendSAMSUNG(uli_HEXCODE, 32);
  }
  if (CHAR_IR_PROTOCOL=="SONY") {
     DEBUG_PRINTLN("SONY");  
     irsend.sendSony(uli_HEXCODE, 32);
  }
  if (CHAR_IR_PROTOCOL=="Whynter") {
     DEBUG_PRINTLN("Whynter");  
     irsend.sendWhynter(uli_HEXCODE, 32);
  }
}

