
## App.java kompilieren
javac -d . -cp lib\* App.java -Xlint:deprecation

## JAR bauen
jar cvf webjob.jar MANIFEST.MF -C . de -C lib . -C . xsd -C . certificate 

## Aufrufen mit Kommandozeilenparametern
.\run.cmd validate # validieren
.\run.cmd transfer # übermitteln
.\run.cmd check # check
.\run.cmd validate check # auch mehere steps sind ausführbar