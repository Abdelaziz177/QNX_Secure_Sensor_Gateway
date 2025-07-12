#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <sys/neutrino.h>
#include <sys/netmgr.h>
#include <string.h>
#include <sys/dispatch.h> //for name_open & name_close

#include <chrono>
#include <thread>

#define SERVER_NAME "SENSOR_CHANNEL"

struct SensorData {
    int temperature;    // Celsius
    int speed;          // km/h
    float gps_lat;      // Latitude
    float gps_lon;      // Longitude
};

int main() {
    srand(time(nullptr)); // Random seed

    // Locate the receiver (secure sender app)
    int coid = name_open(SERVER_NAME, 0);
    if (coid == -1) {
        perror("name_open failed");
        return 1;
    }

    while (true) {
        SensorData data;
        data.temperature = rand() % 40;             // 0 - 39 °C
        data.speed = rand() % 120;                  // 0 - 119 km/h
        data.gps_lat = 30.0f + static_cast<float>(rand()) / RAND_MAX;
        data.gps_lon = 31.0f + static_cast<float>(rand()) / RAND_MAX;

        int status = MsgSend(coid, &data, sizeof(data), NULL, 0);
        if (status == -1) {
            perror("MsgSend failed");
        } else {
            std::cout << "Sensor data sent: Temp=" << data.temperature
                      << ", Speed=" << data.speed
                      << ", GPS=(" << data.gps_lat << "," << data.gps_lon << ")\n";
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    name_close(coid);
    return 0;
}
