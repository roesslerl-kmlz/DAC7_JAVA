package de.kmlz;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import com.azure.core.util.polling.SyncPoller;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoCollection;
import static com.mongodb.client.model.Filters.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class App {
    public static final String CLIENT_ID_PROD = "d615848f-f925-481b-8c33-85373c7f4345";
    public static final String CLIENT_ID_TEST = "95db0b02-3dcc-4c5c-b376-f3cb5b7343e6";

    public static final String SERVER_PROD = "https://mds.bzst.bund.de";
    public static final String SERVER_TEST = "https://mds-ktst.bzst.bund.de";

    public static final String BASEDIR_PROD = "WorkfilesProd";
    public static final String BASEDIR_TEST = "WorkfilesTest";

    public static final String DATABASE_PROD = "prod";
    public static final String DATABASE_TEST = "test";
    public static final String DATABASE_CONNECT_STRING = "mongodb+srv://michael:11IcBiSoCoDaIcLaPwVw44@dac7database.r0ymhfx.mongodb.net/?retryWrites=true&w=majority";

    public static final String PRIVATE_KEY = "/certificate/newKey.pem";
    public static final String CERTIFICATE = "/certificate/cert.pem";
    public static final String PUBLIC_KEY = "/certificate/publicKey.pem";

    public static void main(String[] args) throws Exception {
        
        String server = SERVER_TEST;
        String clientID = CLIENT_ID_TEST;
        String db = DATABASE_TEST;
        if (Arrays.asList(args).contains("--prod")) {
            System.out.println("PROD Environment");
            server = SERVER_PROD;
            clientID = CLIENT_ID_PROD;
            db = DATABASE_PROD;
        }
        
        if (Arrays.asList(args).contains("validate") || Arrays.asList(args).contains("transfer")) {
            validateAndTransfer(Arrays.asList(args).contains("validate"), Arrays.asList(args).contains("transfer"), server, clientID, db);
        }
        if (Arrays.asList(args).contains("check")){
            checkTransfersWithoutSuccess(server, clientID);
        }
     
    }

    private static void validateAndTransfer(boolean validate, boolean transfer, String server, String clientID, String db) throws Exception {
        System.out.println("Connect to Azure");
        // Verbindung zu Azure Blob Storage herstellen
        String blobConnectionString = "DefaultEndpointsProtocol=https;AccountName=kmlzai6065888463;AccountKey=yP9gKrTn2IR260rRNHV2ltEVVW9EqftuEMO6u75QsLleqXR8Ac0zhmuL5TbqEM8f0F77fzlcvdhz+ASttbqIuQ==;EndpointSuffix=core.windows.net";
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString(blobConnectionString).buildClient();
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("dac7");
        
        String directoryName = "XML";
        String directorySentName = "XML_SEND";
        String pathToList = BASEDIR_TEST + "/" + directoryName + "/";

        for (BlobItem blobItem : containerClient.listBlobsByHierarchy(pathToList)) {
            System.out.println("XML-Datei gefunden: " + blobItem.getName());

            if(validate){
                String PathXSD = "/xsd/";
                String XSDFile1 = PathXSD + "DPIXML_v1.0.xsd";
                String XSDFile2 = PathXSD + "dip.xsd";
                String XSDFile3 = PathXSD + "dip-types.xsd";
                String XSDFile4 = PathXSD + "isodpitypes_v1.0.xsd";
                String XSDFile5 = PathXSD + "oecddpitypes_v1.0.xsd";

                var validator = initValidator(XSDFile1, XSDFile2, XSDFile3, XSDFile4, XSDFile5);
                try {
                    validator.validate(new StreamSource(getBlobAsFile(containerClient, blobItem.getName())));
                    System.out.println("true");
                } catch (SAXException e) {
                    System.out.println("false " + e.getMessage());
                    System.out.println("false1 " + e.toString());
                }
            }
            if (transfer){
                File sourceXml = getBlobAsFile(containerClient, blobItem.getName()); 
                String signXMLFile = sourceXml.getName().replace(".xml", "_signed.xml");
                InputStream xml = signXML(sourceXml.getAbsolutePath(), signXMLFile);

                System.out.print("\n");
                String transferNumber = openTransfer(server, clientID);
                System.out.print("Open Transfer with transferNumber: " + transferNumber + "\n");

                sendXML(transferNumber, xml, server, clientID);
                finalizeTransfer(transferNumber, server, clientID);
                Thread.sleep(15000);
                boolean success = checkTransfer(transferNumber, server, clientID);
                storeTransmitFileWithNumber(db, blobItem.getName(), transferNumber, success);
                System.out.print(blobItem.getName() + " - " +  blobItem.getName().replace(directoryName, directorySentName));
                moveFileOnAzure(containerClient, blobItem.getName(), blobItem.getName().replace(directoryName, directorySentName));
            }
        }
    }

    private static File createTempDirectory() throws IOException {
        String tempDir = System.getProperty("java.io.tmpdir");
        String tempSubDirName = "temp_" + System.currentTimeMillis();
        File tempSubDir = new File(tempDir, tempSubDirName);
        if (!tempSubDir.mkdir()) {
            throw new IOException("Failed to create temp directory: " + tempSubDir.getAbsolutePath());
        }
        tempSubDir.deleteOnExit();
        return tempSubDir;
    }

    private static File createTempFileFromResource(String resourcePath, File tempDir) throws IOException {
        InputStream inputStream = App.class.getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new FileNotFoundException("Resource not found: " + resourcePath);
        }
        String fileName = Paths.get(resourcePath).getFileName().toString();
        File tempFile = new File(tempDir, fileName);
        tempFile.deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
        return tempFile;
    }

    private static Validator initValidator(String xsdPath1, String xsdPath2, String xsdPath3, String xsdPath4, String xsdPath5) throws SAXException, IOException {
        File tempDir = createTempDirectory();
        File xsdFile = createTempFileFromResource(xsdPath1, tempDir);
        File xsdFile2 = createTempFileFromResource(xsdPath2, tempDir);
        File xsdFile3 = createTempFileFromResource(xsdPath3, tempDir);
        File xsdFile4 = createTempFileFromResource(xsdPath4, tempDir);
        File xsdFile5 = createTempFileFromResource(xsdPath5, tempDir);

        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema(new Source[] {
            new StreamSource(xsdFile), new StreamSource(xsdFile2), new StreamSource(xsdFile3), new StreamSource(xsdFile4), new StreamSource(xsdFile5)
          });

        return schema.newValidator();
    }

    private static File getBlobAsFile(BlobContainerClient containerClient, String blobName) throws IOException {
        // Get a reference to the blob
        BlobClient blobClient = containerClient.getBlobClient(blobName);

        // Create a temporary file
        File tempFile = File.createTempFile("blob-", ".tmp");
        tempFile.deleteOnExit();

        if (tempFile.exists()) {
            tempFile.delete();
        }
        
        // Download the blob to the temporary file
        blobClient.downloadToFile(tempFile.getAbsolutePath());

        return tempFile;
    }

    private static void moveFileOnAzure(BlobContainerClient containerClient, String sourceBlobName, String destinationBlobName) {
        // Get a reference to the source blob
        BlobClient sourceBlob = containerClient.getBlobClient(sourceBlobName);

        // Get a reference to the destination blob
        BlobClient destinationBlob = containerClient.getBlobClient(destinationBlobName);

        // Start the copy operation
        SyncPoller<BlobCopyInfo, Void> poller = destinationBlob.beginCopy(sourceBlob.getBlobUrl(), Duration.ofSeconds(1));

        // Wait for the copy to complete
        poller.waitForCompletion();

        // Get the copy status after completion
        CopyStatusType copyStatus = poller.poll().getValue().getCopyStatus();
        System.out.println("Copy Status: " + copyStatus);

        // Delete the source blob if the copy was successful
        if (copyStatus.equals(CopyStatusType.SUCCESS)) {
            sourceBlob.delete();
        }
    }

    private static void storeTransmitFileWithNumber(String db, String filename, String transferNumber, boolean success) {
        // Verbindung zur MongoDB herstellen
        try (MongoClient mongoClient = MongoClients.create(DATABASE_CONNECT_STRING)) {
            MongoDatabase database = mongoClient.getDatabase(db);
            MongoCollection<org.bson.Document> collection = database.getCollection("TransmissionFileToNumber");

            org.bson.Document doc = new org.bson.Document("filename", filename)
                                                .append("transferNumber", transferNumber)
                                                .append("checkSuccess", success);
            collection.insertOne(doc);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void storeCheckSuccess(String db, String transferNumber) {
        try (MongoClient mongoClient = MongoClients.create(DATABASE_CONNECT_STRING)) {
            MongoDatabase database = mongoClient.getDatabase(db);
            MongoCollection<org.bson.Document> collection = database.getCollection("TransmissionFileToNumber");

            org.bson.Document filter = new org.bson.Document("transferNumber", transferNumber);
            org.bson.Document update = new org.bson.Document("$set", new org.bson.Document("checkSuccess", true));

            collection.updateOne(filter, update);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static List<String> readTransferNumbers() {
        List<String> transferNumbers = new ArrayList<>();
        try (MongoClient mongoClient = MongoClients.create(DATABASE_CONNECT_STRING)) {
            MongoDatabase database = mongoClient.getDatabase(DATABASE_TEST);
            MongoCollection<org.bson.Document> collection = database.getCollection("TransmissionFileToNumber");

            for (org.bson.Document document : collection.find(eq("checkSuccess", false))) {
                transferNumbers.add(document.getString("transferNumber"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return transferNumbers;
    }

    public static void checkTransfersWithoutSuccess(String url, String ClientID) throws Exception{
        List<String> transferNumbers = readTransferNumbers();
        for (String transferNumber : transferNumbers) {
            try {
                checkTransfer(transferNumber, url, ClientID);
                storeCheckSuccess(DATABASE_TEST, transferNumber);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static boolean checkTransfer(String transferNumber, String url, String clientID) throws Exception{
        System.out.println("\n");
        System.out.println("Überprüfung des Transfers / Abfrage Protokoll: ");
        String Access = gettingAccessToken(url, clientID);

        URI _url = new URI(url + "/dip/md/" + transferNumber + "/protocol");

        HttpRequest request = HttpRequest.newBuilder()
            .uri(_url)
            .header("Authorization", "bearer " + Access)
            .GET()
            .build();
        
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, BodyHandlers.ofString());

        int status = response.statusCode();

        if (status != 200) {
            switch (status) {
                case 400:
                    System.out.println(status + " - Ungültige Datentransfernummer");
                    break;
                case 401:
                    System.out.println(status + " - Ungültiger Authorization Header");
                    break;
                case 404:
                    System.out.println(status + " - Datei nicht gefunden, Protokoll liegt noch nicht vor");
                    break;
                case 424:
                    System.out.println(status + " - Der Datenübermittler ist dem Vorgang nicht zugeordnet");
                    break;
                default:
                    break;
            }
            return false;
        }

        System.out.println("Transfer: " + status);
        System.out.println("Transfer: " + response.body());
        return true;
    }

    public static void finalizeTransfer(String Transfernumber, String url, String ClientID) throws Exception{
        
        System.out.println("Beende Transfer \n");
        String Access = gettingAccessToken(url, ClientID);

        URI uri = new URI(url + "/dip/md/" + Transfernumber + "/finish");

        HttpRequest request = HttpRequest.newBuilder()
            .uri(uri)
            .header("Authorization", "bearer " + Access)
            .method("PATCH", BodyPublishers.noBody())
            .build();
        
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, BodyHandlers.ofString());

        int status = response.statusCode();

        if (status != 200) {
            switch (status) {
                case 400:
                    System.out.println(status + " - Ungültige Datentransfernummer");
                    break;
                    case 401:
                    System.out.println(status + " - Ungültiger Authorization Header");
                    break;
                    case 410:
                    System.out.println(status + " - Datentransfer wurde bereits beendet");
                    break;
                    case 424:
                    System.out.println(status + " - Der Datenübermittler ist dem Vorgang nicht zugeordnet");
                    break;
                    case 500:
                    System.out.println(status + " - Interner Fehler");
                    break;
                default:
                    break;
            }
        }
        else{
            System.out.println(status + " - Anfrage erfolgreich");
        }
    }

    public static void sendXML(String Transfernumber, InputStream requestedXml, String url, String ClientID) throws Exception{
        
        String Access = gettingAccessToken(url, ClientID);

        URI uri = new URI(url + "/dip/md/" + Transfernumber + "/xml");

        HttpURLConnection conn = (HttpURLConnection)uri.toURL().openConnection();
        conn.setRequestMethod("PUT");
        conn.setDoOutput(true);
        conn.setRequestProperty("Authorization", "bearer " + Access);
        conn.setRequestProperty("Content-Type", "APPLICATION/OCTET-STREAM");
        OutputStream outStream = conn.getOutputStream();
        requestedXml.transferTo(outStream);
        outStream.close();

        int status = conn.getResponseCode();

        

        if (status != 200) {
            switch (status) {
                case 400:
                    System.out.println(status + " - Ungültige Datentransfernummer");
                    break;
                    case 401:
                    System.out.println(status + " - Ungültiger Authorization Header");
                    break;
                    case 410:
                    System.out.println(status + " - Datentransfer wurde bereits beendet");
                    break;
                    case 424:
                    System.out.println(status + " - Der Datenübermittler ist dem Vorgang nicht zugeordnet");
                    break;
                    case 500:
                    System.out.println(status + " - Interner Fehler");
                    break;
                default:
                    break;
            }
        } else {
            System.out.println(status + " - Einreichung erfolgreich");
        }

        Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (int c; (c = in.read()) >= 0;) {
            sb.append((char)c);
        }
        String response = sb.toString();

        System.out.println("Send XML response: \n" + response);
    } 

    public static String openTransfer(String url, String ClientID) throws Exception{
        System.out.println("Start des Datentrasfers:");
        String Access = gettingAccessToken(url, ClientID);

        URI uri = new URI(url + "/dip/start/dac7");

        HttpURLConnection conn = (HttpURLConnection)uri.toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Authorization", "bearer " + Access);
        int status = conn.getResponseCode();

        if (status != 201) {
            switch (status) {
                case 429:
                    System.out.println(status + " - Der Client hat zu viele Anfragen in der letzten Minute gesendet");
                    break;
                case 401:
                    System.out.println(status + " - Ungültiger Authorization");
                    break;
                case 404:
                    System.out.println(status + " - Zielfachverfahren nicht gefunden");
                    break;
                case 500:
                    System.out.println(status + " - Interner Fehler");
                    break;
                default:
                    break;
            }
        }
        else{
            System.out.println(status + " - Datentransfer erfolgreich initiiert");
        }

        Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (int c; (c = in.read()) >= 0;)
            sb.append((char)c);
        String response = sb.toString();

        return response;
  
    }

    public static String gettingAccessToken(String url, String ClientID) throws Exception{
      
        String token = calculateJWT(url, ClientID);

        Map<String,Object> params = new LinkedHashMap<>();
        params.put("grant_type", "client_credentials");
        params.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        params.put("client_assertion", token);

        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String,Object> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        byte[] postDataBytes = postData.toString().getBytes("UTF-8");

        URI uri = new URI(url + "/auth/realms/mds/protocol/openid-connect/token");

        HttpURLConnection conn = (HttpURLConnection)uri.toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        conn.getOutputStream().write(postDataBytes);

        int status = conn.getResponseCode();
        if (status != 200) {
            throw new IOException("Post failed with error code " + status);
        }

        Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (int c; (c = in.read()) >= 0;)
            sb.append((char)c);
        String response = sb.toString();

        JSONObject jsonObject = new JSONObject(response);
        String access_token = jsonObject.getString("access_token");

        return access_token;
    }

    public static RSAPublicKey readX509PublicKey() throws Exception {
        String key = new String(readAllBytes(App.class.getResourceAsStream(PUBLIC_KEY)), Charset.defaultCharset());
    
        String publicKeyPEM = key
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replaceAll(System.lineSeparator(), "")
          .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM.trim());
    
        KeyFactory keyFactory = KeyFactory.getInstance("RSASSA-PSS");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public static String calculateJWT(String url, String ClientID) throws Exception {

        String Enviroment = url + "/auth/realms/mds";
        String PrivateKey = getKey(PRIVATE_KEY);

        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey)readX509PublicKey(), (RSAPrivateKey)getPrivateKeyFromString(PrivateKey));
    
        String originalToken = JWT.create()
                .withIssuer(ClientID)
                .withSubject(ClientID)
                .withAudience(Enviroment)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + (5 * 60 * 1000L)))
                .withJWTId(UUID.randomUUID().toString())
                .withNotBefore(new Date(System.currentTimeMillis() - 60 * 1000L))
                .sign(algorithm);

        return originalToken;
    }

    private static InputStream signXML(String XMLFile, String signXMLFile) throws Exception {
        String PrivateKey = getKey(PRIVATE_KEY);
        var _PrivateKey = getPrivateKeyFromString(PrivateKey);

        String dipXML = readXML(XMLFile);
        InputStream unsignDipStream = new ByteArrayInputStream(dipXML.getBytes(StandardCharsets.UTF_8));

        String digestMethode = DigestMethod.SHA256;
        String signatureMethode = SignatureMethod.SHA256_RSA_MGF1;

        var documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);

        Document dipXMLDocument = documentBuilderFactory.newDocumentBuilder().parse(unsignDipStream);
        Document newDocument = documentBuilderFactory.newDocumentBuilder().newDocument();

        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
        var DomSignContext = new DOMSignContext(_PrivateKey, newDocument);
        DomSignContext.setDefaultNamespacePrefix("ds");

        var reference = xmlSignatureFactory.newReference("#object", xmlSignatureFactory.newDigestMethod(digestMethode, null), List.of(), null, null);
        var content = new DOMStructure(dipXMLDocument.getDocumentElement());
        var signObject = xmlSignatureFactory.newXMLObject(Collections.singletonList(content), "object", null, null);

        var signInfo = xmlSignatureFactory.newSignedInfo(
                xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                xmlSignatureFactory.newSignatureMethod(signatureMethode, null), Collections.singletonList(reference));
        
        KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        //Certificate
        X509Certificate certificate = convertStringToX509Cert(CERTIFICATE);
        X509Data x509Data = keyInfoFactory.newX509Data(Arrays.asList(certificate.getSubjectX500Principal().getName(), certificate));

        List<XMLStructure> data = Arrays.asList(x509Data);
        var keyInfo = keyInfoFactory.newKeyInfo(data); // muss aus Zertifikat erzeugt werden - KeyInfo

        var xmlSignature = xmlSignatureFactory.newXMLSignature(signInfo, keyInfo, Collections.singletonList(signObject), null, null);

        xmlSignature.sign(DomSignContext);

        var xmlSource = new DOMSource(newDocument);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        var Outputtarget = new StreamResult(outputStream);
        TransformerFactory.newInstance().newTransformer().transform(xmlSource, Outputtarget);

        var Result = new ByteArrayInputStream(outputStream.toByteArray());

        OutputStream os = new FileOutputStream(signXMLFile);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(xmlSource, new StreamResult(os));

        return Result;
        
    }

    private static String readXML(String File)throws IOException{
        BufferedReader reader = new BufferedReader(new FileReader(File));
        String line = reader.readLine();
        StringBuilder stringBuilder = new StringBuilder();
        while (line != null) {
            stringBuilder.append(line).append("\n");
            line = reader.readLine();
        }
        reader.close();
        return stringBuilder.toString();
    }

    private static X509Certificate convertStringToX509Cert(String filename) throws Exception{
        InputStream targetStream = App.class.getResourceAsStream(filename);
        return (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(targetStream);
}

    private static String getKey(String filename) throws IOException {
        // Read key from file
        InputStream inputStream = App.class.getResourceAsStream(filename);
        String key = new String(readAllBytes(inputStream), Charset.defaultCharset());
        String privateKeyPEM = key
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END PRIVATE KEY-----", "");
        
        return privateKeyPEM;
    }

    private static byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, bytesRead);
        }
        return buffer.toByteArray();
    }

    public static RSAPrivateKey getPrivateKeyFromString(String key) throws IOException, GeneralSecurityException {
    
        byte[] encoded = Base64.getDecoder().decode(key.trim());
        KeyFactory kf = KeyFactory.getInstance("RSA");
    
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

        RSAPrivateKey privKey = (RSAPrivateKey)kf.generatePrivate(keySpec);

        return privKey;
    }
}
