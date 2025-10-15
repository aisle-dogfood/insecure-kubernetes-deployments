package com.example.insecurejava;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.InvalidClassException;
import java.io.ObjectStreamClass;

@RestController
public class UnsafeDeserializationController {

    @PostMapping("/unsafeDeserialize")
    public ResponseEntity<String> unsafeDeserialization(@RequestBody byte[] data) {
        try {
            // Create a secure implementation of ObjectInputStream
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            SecureObjectInputStream ois = new SecureObjectInputStream(bais);
            
            // Only deserialize objects from trusted packages
            Object deserializedObject = ois.readObject();
            return ResponseEntity.ok("Object deserialized: " + deserializedObject.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error during deserialization");
        }
    }
    
    // Custom secure ObjectInputStream that validates classes before deserialization
    private static class SecureObjectInputStream extends ObjectInputStream {
        private static final String[] ALLOWED_PACKAGES = {
            "java.lang.",
            "java.util."
            // Add other trusted packages as needed
        };

        public SecureObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            
            // Validate that the class being deserialized is from an allowed package
            boolean isAllowed = false;
            for (String allowedPackage : ALLOWED_PACKAGES) {
                if (className.startsWith(allowedPackage)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (!isAllowed) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
            
            return super.resolveClass(desc);
        }
    }
}
