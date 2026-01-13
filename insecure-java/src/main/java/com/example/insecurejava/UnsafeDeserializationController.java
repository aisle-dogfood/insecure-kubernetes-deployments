package com.example.insecurejava;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils; // Import HtmlUtils for output sanitization
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

@RestController
public class UnsafeDeserializationController {

    @PostMapping("/unsafeDeserialize")
    public ResponseEntity<String> unsafeDeserialization(@RequestBody byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object deserializedObject = ois.readObject();
            // SECURITY: Sanitize the output to prevent XSS attacks
            // The toString() method of deserialized objects could contain malicious HTML/JavaScript
            // Using HtmlUtils.htmlEscape to encode special characters and prevent script execution
            return ResponseEntity.ok("Object deserialized: " + HtmlUtils.htmlEscape(deserializedObject.toString()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error during deserialization");
        }
    }
}
