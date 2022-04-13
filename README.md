
# TCA Plugin - SonarQube
This is a plugin project for [TCA](https://github.com/Tencent/CodeAnalysis) integrating [SonarQube](https://www.sonarqube.org/downloads/).

## Depedences
- sonarqube-8.9.8.54436
- sonar-scanner-4.2.0.1873

## Usage
### Quick start
1. setup TCA;
2. download this project;
3. load the rules json in [config](config/) diretory for TCA Server;
4. On the node management page on the TCA Server, configure the SonarQube tool process for the machine node;
5. Create the corresponding TCA project on the TCA Server, add the SonarQube rules to the analysis plan, and start the analysis.

### Options
#### Java no build mode
need sonar-java-plugin-5.14.0.18788.jar

#### SonarQube need NodeJs
For languages like javascript/typescript/css, SonarQube requires the Node.js environment:
```shell
export PATH=${NODE_HOME}/bin:${PATH}
```

#### MODE
This project is divided into two operating modes, local mode and COMMON mode, the default local mode.
##### LOCAL mode
Start the SonarQube service locally, and then execute the analysis task.

##### COMMON mode
Supports connecting to remote SonarQube services.
1. In the [setting.py](src/settings.py) file, configure the information of SQ_COMMON_USER following SQ_LOCAL_USER
2. Set environment variables in the analysis scheme of the TCA project:
```shell
export SQ_TYPE=COMMON
```
3. Then start the task


#### Upgrade SonarQube version
1. Download the corresponding version of the SonarQube package and unzip it in the tools/common directory
2. Copy the [run.sh](tools/common/sonarqube-8.9.8.54436/bin/run.sh) file to the bin directory of the decompressed SonarQube package
3. Modify the tool location in [sq.py](src/util/sq.py#L99)

#### Change account and password
It is not recommended to use the SonarQube default password, so after successfully executing this project, it is recommended to modify the SonarQube password:
1. Start SonarQube, change the password on the SonarQube page, and get the corresponding token
2. In the [setting.py](src/settings.py) file, modify the username field corresponding to SQ_LOCAL_USER and SQ_COMMON_USER to token and password to ""




