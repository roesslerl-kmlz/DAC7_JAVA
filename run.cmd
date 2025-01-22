@echo off
echo %1
set JAVA_HOME=C:\Program Files\Java\jdk-21
set PATH=%JAVA_HOME%\bin;%PATH%
java -cp webjob.jar;lib\* de.kmlz.App %1 %2 %3 %4 %5 %6 %7 %8 %9