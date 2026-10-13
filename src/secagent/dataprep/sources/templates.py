"""
Sentetik örnek şablonları — CVEfixes'ta bulunmayan/az olan teknolojiler için
(kotlin, swift, docker, terraform, kubernetes).

Her şablon: zafiyetli kod + düzeltilmiş kod (+ isteğe bağlı "yanlış alarm" kodu).
Yer tutucular <<ad>> biçimindedir (kod/YAML/HCL süslü parantezleriyle çakışmasın).
Yalnızca SAVUNMA verisidir: zafiyetli kod bir kalıbı gösterir, istismar içermez.

Yanlış alarm (fp_code) şablonları ancak GERÇEK bir tarayıcı o CWE için alarm
verirse veri setine girer (bkz. synthetic.py / dataprep/build.py).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Template:
    id: str
    language: str
    file: str
    cwe: str
    severity: str
    title: str
    fix: str
    evidence: str                 # zafiyetli kodda geçen satır parçası
    vulnerable: str
    fixed: str
    function: str | None = None
    fp_code: str | None = None
    fp_evidence: str | None = None
    fp_reason: str | None = None


KOTLIN_REPO = """import java.sql.Connection

class <<cls>>(private val conn: Connection) {
    fun <<fn>>(<<var>>: String): List<String> {
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT name FROM <<tbl>> WHERE id = '" + <<var>> + "'")
        val out = mutableListOf<String>()
        while (rs.next()) out.add(rs.getString(1))
        return out
    }
}
"""
KOTLIN_REPO_FIXED = """import java.sql.Connection

class <<cls>>(private val conn: Connection) {
    fun <<fn>>(<<var>>: String): List<String> {
        conn.prepareStatement("SELECT name FROM <<tbl>> WHERE id = ?").use { stmt ->
            stmt.setString(1, <<var>>)
            val rs = stmt.executeQuery()
            val out = mutableListOf<String>()
            while (rs.next()) out.add(rs.getString(1))
            return out
        }
    }
}
"""
KOTLIN_REPO_FP = """import java.sql.Connection

private const val TABLE = "<<tbl>>"

class <<cls>>(private val conn: Connection) {
    fun <<fn>>(): List<String> {
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT name FROM " + TABLE + " WHERE active = 1")
        val out = mutableListOf<String>()
        while (rs.next()) out.add(rs.getString(1))
        return out
    }
}
"""

KOTLIN_MD5 = """import java.security.MessageDigest

class <<cls>> {
    fun <<fn>>(password: String): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
"""
KOTLIN_MD5_FIXED = """import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class <<cls>> {
    fun <<fn>>(password: String): String {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val spec = PBEKeySpec(password.toCharArray(), salt, 210_000, 256)
        val hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return (salt + hash).joinToString("") { "%02x".format(it) }
    }
}
"""
KOTLIN_MD5_FP = """import java.security.MessageDigest

class <<cls>> {
    // Yalnızca önbellek anahtarı/ETag için; güvenlik amaçlı kullanılmıyor.
    fun <<fn>>(content: ByteArray): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(content).joinToString("") { "%02x".format(it) }
    }
}
"""

KOTLIN_EXEC = """class <<cls>> {
    fun <<fn>>(host: String): String {
        val proc = Runtime.getRuntime().exec("ping -c 1 " + host)
        return proc.inputStream.bufferedReader().readText()
    }
}
"""
KOTLIN_EXEC_FIXED = """class <<cls>> {
    private val hostPattern = Regex("^[A-Za-z0-9.-]{1,253}$")

    fun <<fn>>(host: String): String {
        require(hostPattern.matches(host)) { "geçersiz ana makine adı" }
        val proc = ProcessBuilder("ping", "-c", "1", host).start()
        return proc.inputStream.bufferedReader().readText()
    }
}
"""
KOTLIN_EXEC_FP = """private const val LOG_DIR = "/var/log/<<name>>"

class <<cls>> {
    fun <<fn>>(): String {
        val proc = Runtime.getRuntime().exec("ls -l " + LOG_DIR)
        return proc.inputStream.bufferedReader().readText()
    }
}
"""

KOTLIN_PW = """import java.sql.DriverManager

class <<cls>> {
    private val dbPassword = "<<secret>>"

    fun <<fn>>() = DriverManager.getConnection("jdbc:postgresql://db/<<tbl>>", "app", dbPassword)
}
"""
KOTLIN_PW_FIXED = """import java.sql.DriverManager

class <<cls>> {
    private val dbPassword = System.getenv("DB_PASSWORD")
        ?: error("DB_PASSWORD ortam değişkeni tanımlı değil")

    fun <<fn>>() = DriverManager.getConnection("jdbc:postgresql://db/<<tbl>>", "app", dbPassword)
}
"""

KOTLIN_PATH = """import java.io.File

class <<cls>>(private val baseDir: String) {
    fun <<fn>>(<<var>>: String): String = File(baseDir + "/" + <<var>>).readText()
}
"""
KOTLIN_PATH_FIXED = """import java.io.File

class <<cls>>(private val baseDir: String) {
    fun <<fn>>(<<var>>: String): String {
        val root = File(baseDir).canonicalFile
        val target = File(root, <<var>>).canonicalFile
        require(target.path.startsWith(root.path + File.separator)) { "izin verilmeyen yol" }
        return target.readText()
    }
}
"""

SWIFT_MD5 = """import CryptoKit
import Foundation

struct <<cls>> {
    func <<fn>>(_ password: String) -> String {
        let digest = Insecure.MD5.hash(data: Data(password.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
"""
SWIFT_MD5_FIXED = """import CryptoKit
import Foundation

struct <<cls>> {
    func <<fn>>(_ password: String, salt: Data) -> String {
        let key = SymmetricKey(data: Data(password.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: salt, using: key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }
}
"""
SWIFT_MD5_FP = """import CryptoKit
import Foundation

struct <<cls>> {
    // Yalnızca indirilen dosyanın bütünlük özetini göstermek için; güvenlik kararı vermez.
    func <<fn>>(_ data: Data) -> String {
        let digest = Insecure.MD5.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
"""

SWIFT_KEY = """import Foundation

struct <<cls>> {
    let apiKey = "<<secret>>"

    func <<fn>>() -> URLRequest {
        var request = URLRequest(url: URL(string: "https://api.example.com/<<tbl>>")!)
        request.setValue("Bearer \\(apiKey)", forHTTPHeaderField: "Authorization")
        return request
    }
}
"""
SWIFT_KEY_FIXED = """import Foundation
import Security

struct <<cls>> {
    private func apiKey() -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: "api-key",
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func <<fn>>() -> URLRequest? {
        guard let key = apiKey() else { return nil }
        var request = URLRequest(url: URL(string: "https://api.example.com/<<tbl>>")!)
        request.setValue("Bearer \\(key)", forHTTPHeaderField: "Authorization")
        return request
    }
}
"""

SWIFT_TLS = """import Foundation

final class <<cls>>: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
"""
SWIFT_TLS_FIXED = """import Foundation

final class <<cls>>: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.performDefaultHandling, nil)
    }
}
"""

SWIFT_DEFAULTS = """import Foundation

struct <<cls>> {
    func <<fn>>(<<var>>: String, password: String) {
        UserDefaults.standard.set(password, forKey: "password")
        UserDefaults.standard.set(<<var>>, forKey: "username")
    }
}
"""
SWIFT_DEFAULTS_FIXED = """import Foundation
import Security

struct <<cls>> {
    func <<fn>>(<<var>>: String, password: String) {
        UserDefaults.standard.set(<<var>>, forKey: "username")
        let item: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrAccount as String: <<var>>,
                                   kSecValueData as String: Data(password.utf8),
                                   kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        SecItemAdd(item as CFDictionary, nil)
    }
}
"""

SWIFT_ARCHIVE = """import Foundation

struct <<cls>> {
    func <<fn>>(_ data: Data) -> Any? {
        return NSKeyedUnarchiver.unarchiveObject(with: data)
    }
}
"""
SWIFT_ARCHIVE_FIXED = """import Foundation

struct <<cls>> {
    func <<fn>>(_ data: Data) -> NSDictionary? {
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: NSDictionary.self, from: data)
    }
}
"""

DOCKER_ROOT = """FROM <<image>>
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
USER root
CMD ["python", "main.py"]
"""
DOCKER_ROOT_FIXED = """FROM <<image>>
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --no-create-home appuser
USER appuser
CMD ["python", "main.py"]
"""

DOCKER_ENV = """FROM <<image>>
WORKDIR /app
ENV DB_PASSWORD="<<secret>>"
COPY . /app
RUN useradd --system --no-create-home appuser
USER appuser
CMD ["python", "main.py"]
"""
DOCKER_ENV_FIXED = """FROM <<image>>
WORKDIR /app
COPY . /app
RUN useradd --system --no-create-home appuser
USER appuser
# DB_PASSWORD çalışma anında ortam/secret yöneticisinden verilir (docker run -e / secrets)
CMD ["python", "main.py"]
"""

DOCKER_CURL = """FROM <<image>>
WORKDIR /app
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -sSL https://get.example.com/install.sh | sh
COPY . /app
RUN useradd --system --no-create-home appuser
USER appuser
CMD ["python", "main.py"]
"""
DOCKER_CURL_FIXED = """FROM <<image>>
WORKDIR /app
COPY install.sh /tmp/install.sh
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo "<<sha>>  /tmp/install.sh" | sha256sum -c - && sh /tmp/install.sh && rm /tmp/install.sh
COPY . /app
RUN useradd --system --no-create-home appuser
USER appuser
CMD ["python", "main.py"]
"""

DOCKER_CHMOD = """FROM <<image>>
WORKDIR /app
COPY . /app
RUN chmod -R 777 /app
RUN useradd --system --no-create-home appuser
USER appuser
CMD ["python", "main.py"]
"""
DOCKER_CHMOD_FIXED = """FROM <<image>>
WORKDIR /app
COPY . /app
RUN useradd --system --no-create-home appuser && chown -R appuser:appuser /app && chmod -R u=rwX,g=rX,o= /app
USER appuser
CMD ["python", "main.py"]
"""

TF_SSH = """resource "aws_security_group" "<<name>>" {
  name   = "<<name>>-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
TF_SSH_FIXED = """resource "aws_security_group" "<<name>>" {
  name   = "<<name>>-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "SSH yalnızca yönetim ağından"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}
"""
TF_ALB_FP = """resource "aws_security_group" "<<name>>" {
  name        = "<<name>>-alb"
  description = "Herkese açık web yük dengeleyici"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

TF_EBS = """resource "aws_ebs_volume" "<<name>>" {
  availability_zone = "eu-west-2a"
  size              = <<size>>
  encrypted         = false
}
"""
TF_EBS_FIXED = """resource "aws_ebs_volume" "<<name>>" {
  availability_zone = "eu-west-2a"
  size              = <<size>>
  encrypted         = true
  kms_key_id        = var.kms_key_arn
}
"""

TF_S3_BASE = """resource "aws_s3_bucket" "<<name>>" {
  bucket = "<<name>>-data"
}

resource "aws_s3_bucket_versioning" "<<name>>" {
  bucket = aws_s3_bucket.<<name>>.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "<<name>>" {
  bucket = aws_s3_bucket.<<name>>.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}
"""
TF_S3 = TF_S3_BASE + """
resource "aws_s3_bucket_acl" "<<name>>" {
  bucket = aws_s3_bucket.<<name>>.id
  acl    = "public-read"
}
"""
TF_S3_FIXED = TF_S3_BASE + """
resource "aws_s3_bucket_public_access_block" "<<name>>" {
  bucket                  = aws_s3_bucket.<<name>>.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""

TF_S3_FP = TF_S3_BASE + """
resource "aws_s3_bucket_website_configuration" "<<name>>" {
  bucket = aws_s3_bucket.<<name>>.id
  index_document {
    suffix = "index.html"
  }
}

# Yalnızca herkese açık statik site varlıkları; hassas veri içermez.
resource "aws_s3_bucket_acl" "<<name>>" {
  bucket = aws_s3_bucket.<<name>>.id
  acl    = "public-read"
}
"""

TF_DB_HARDENING = """  storage_encrypted                   = true
  kms_key_id                          = var.kms_key_arn
  backup_retention_period             = 7
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = var.kms_key_arn
  publicly_accessible                 = false
"""
TF_DBPW = """resource "aws_db_instance" "<<name>>" {
  identifier        = "<<name>>"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = <<size>>
  username          = "app"
  password          = "<<secret>>"
""" + TF_DB_HARDENING + "}\n"
TF_DBPW_FIXED = """variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_db_instance" "<<name>>" {
  identifier        = "<<name>>"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = <<size>>
  username          = "app"
  password          = var.db_password
""" + TF_DB_HARDENING + "}\n"

def _pod(*, name="<<name>>", namespace="", privileged=False, non_root=True, run_as_user=10001,
         host_network=False, env="", volumes="", mounts="") -> str:
    """Varsayılan olarak sertleştirilmiş Pod; şablonlar yalnızca TEK kusuru açar,
    böylece hedef dışı alarmlar çıkmaz."""
    meta_ns = f"\n  namespace: {namespace}" if namespace else ""
    pod_ctx = ("  securityContext:\n    runAsNonRoot: true\n    seccompProfile:\n"
               "      type: RuntimeDefault\n") if non_root else ""
    ctx_user = ("        runAsNonRoot: true\n" if non_root else "") + \
               f"        runAsUser: {run_as_user}\n"
    return (
        "apiVersion: v1\nkind: Pod\nmetadata:\n"
        f"  name: {name}{meta_ns}\nspec:\n"
        + ("  hostNetwork: true\n" if host_network else "") + pod_ctx +
        "  containers:\n"
        f"    - name: {name}\n      image: <<image>>\n      securityContext:\n"
        f"        privileged: {'true' if privileged else 'false'}\n" + ctx_user +
        "        runAsGroup: 10001\n        allowPrivilegeEscalation: false\n"
        "        readOnlyRootFilesystem: true\n        capabilities:\n          drop: [\"ALL\"]\n"
        "        seccompProfile:\n          type: RuntimeDefault\n"
        "      resources:\n        limits:\n          cpu: 500m\n          memory: 256Mi\n"
        "        requests:\n          cpu: 100m\n          memory: 128Mi\n"
        + mounts + env + volumes)


K8S_FIXED = _pod()
K8S_PRIV = _pod(privileged=True)
K8S_ROOT = _pod(non_root=False, run_as_user=0)
K8S_HOSTNET = _pod(host_network=True)
K8S_HOSTNET_FP = _pod(name="<<name>>-node-exporter", namespace="monitoring", host_network=True)
K8S_PRIV_FP = _pod(name="<<name>>-csi-node", namespace="csi-system", privileged=True)
K8S_HOSTPATH = _pod(
    mounts="      volumeMounts:\n        - name: host-root\n          mountPath: /host\n",
    volumes="  volumes:\n    - name: host-root\n      hostPath:\n        path: /\n")
K8S_HOSTPATH_FIXED = _pod(
    mounts="      volumeMounts:\n        - name: scratch\n          mountPath: /tmp\n",
    volumes="  volumes:\n    - name: scratch\n      emptyDir: {}\n")
K8S_HOSTPATH_FP = _pod(
    name="<<name>>-log-shipper", namespace="logging",
    mounts="      volumeMounts:\n        - name: varlog\n          mountPath: /var/log\n          readOnly: true\n",
    volumes="  volumes:\n    - name: varlog\n      hostPath:\n        path: /var/log\n        type: Directory\n")
K8S_SECRET = _pod(env="      env:\n        - name: DB_PASSWORD\n          value: \"<<secret>>\"\n")
K8S_SECRET_FIXED = _pod(env=(
    "      env:\n        - name: DB_PASSWORD\n          valueFrom:\n            secretKeyRef:\n"
    "              name: <<name>>-db\n              key: password\n"))
K8S_SOCK = _pod(
    mounts="      volumeMounts:\n        - name: docker-sock\n          mountPath: /var/run/docker.sock\n",
    volumes="  volumes:\n    - name: docker-sock\n      hostPath:\n        path: /var/run/docker.sock\n")


def _t(id, language, file, cwe, severity, title, fix, evidence, vulnerable, fixed,
       function=None, fp_code=None, fp_evidence=None, fp_reason=None) -> Template:
    return Template(id, language, file, cwe, severity, title, fix, evidence,
                    vulnerable, fixed, function, fp_code, fp_evidence, fp_reason)


TEMPLATES: tuple[Template, ...] = (
    _t("kt-sqli", "kotlin", "<<cls>>.kt", "CWE-89", "high",
       "Kullanıcı girdisi SQL dizgisine birleştiriliyor",
       "createStatement + dizge birleştirme yerine prepareStatement kullan ve girdiyi setString ile parametre olarak bağla.",
       "stmt.executeQuery(", KOTLIN_REPO, KOTLIN_REPO_FIXED, "<<fn>>",
       KOTLIN_REPO_FP, "stmt.executeQuery(",
       "Sorguya yalnızca derleme zamanı sabiti (const val TABLE) birleştiriliyor; kullanıcı girdisi yok."),
    _t("kt-md5", "kotlin", "<<cls>>.kt", "CWE-327", "medium",
       "Parola özetlemede kırık MD5 algoritması",
       "Parolalar için tuzlu ve yavaş bir KDF kullan (PBKDF2WithHmacSHA256, bcrypt veya Argon2); MD5 kullanma.",
       'MessageDigest.getInstance("MD5")', KOTLIN_MD5, KOTLIN_MD5_FIXED, "<<fn>>",
       KOTLIN_MD5_FP, 'MessageDigest.getInstance("MD5")',
       "MD5 yalnızca içerik önbellek anahtarı/ETag üretmek için kullanılıyor; parola veya güvenlik kararı için değil."),
    _t("kt-exec", "kotlin", "<<cls>>.kt", "CWE-78", "critical",
       "Kullanıcı girdisi işletim sistemi komutuna birleştiriliyor",
       "Dizge birleştirmek yerine ProcessBuilder'a argüman listesi ver ve ana makine adını beyaz liste/regex ile doğrula.",
       'Runtime.getRuntime().exec("ping -c 1 " + host)', KOTLIN_EXEC, KOTLIN_EXEC_FIXED, "<<fn>>",
       KOTLIN_EXEC_FP, 'Runtime.getRuntime().exec("ls -l " + LOG_DIR)',
       "Komuta eklenen değer derleme zamanı sabiti (const val LOG_DIR); kullanıcı girdisi komuta girmiyor."),
    _t("kt-pw", "kotlin", "<<cls>>.kt", "CWE-798", "high",
       "Veritabanı parolası kaynak koda gömülü",
       "Parolayı kaynak koddan çıkar; ortam değişkeni veya secret yöneticisinden oku ve açığa çıkmış parolayı değiştir.",
       'private val dbPassword = "<<secret>>"', KOTLIN_PW, KOTLIN_PW_FIXED, "<<cls>>"),
    _t("kt-path", "kotlin", "<<cls>>.kt", "CWE-22", "high",
       "Kullanıcı girdisiyle oluşturulan dosya yolu doğrulanmıyor",
       "Yolu canonicalFile ile çöz ve sonucun izin verilen kök dizinin altında kaldığını doğrula.",
       'File(baseDir + "/" + <<var>>).readText()', KOTLIN_PATH, KOTLIN_PATH_FIXED, "<<fn>>"),

    _t("sw-md5", "swift", "<<cls>>.swift", "CWE-327", "medium",
       "Parola özetlemede kırık MD5 algoritması",
       "Parolalar için tuzlu ve yavaş bir KDF kullan; MD5 yerine en az SHA-256 tabanlı, anahtarlı bir yapı kur.",
       "Insecure.MD5.hash(data: Data(password.utf8))", SWIFT_MD5, SWIFT_MD5_FIXED, "<<fn>>",
       SWIFT_MD5_FP, "Insecure.MD5.hash(data: data)",
       "MD5 yalnızca indirilen dosyanın bütünlük özetini göstermek için kullanılıyor; güvenlik kararı vermiyor."),
    _t("sw-key", "swift", "<<cls>>.swift", "CWE-798", "high",
       "API anahtarı kaynak koda gömülü",
       "Anahtarı koddan çıkar, Keychain'de sakla (veya sunucu tarafından kısa ömürlü olarak ver) ve açığa çıkmış anahtarı iptal et.",
       'let apiKey = "<<secret>>"', SWIFT_KEY, SWIFT_KEY_FIXED, "<<cls>>"),
    _t("sw-tls", "swift", "<<cls>>.swift", "CWE-295", "high",
       "Sunucu sertifikası doğrulanmadan her sertifika kabul ediliyor",
       "Özel kimlik doğrulama gerekmiyorsa .performDefaultHandling döndür; sertifika sabitleme gerekiyorsa sertifikayı açıkça karşılaştır.",
       "completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))",
       SWIFT_TLS, SWIFT_TLS_FIXED, None),
    _t("sw-defaults", "swift", "<<cls>>.swift", "CWE-312", "medium",
       "Parola UserDefaults içinde düz metin saklanıyor",
       "Parolayı UserDefaults yerine Keychain'e (kSecAttrAccessibleWhenUnlockedThisDeviceOnly) yaz.",
       'UserDefaults.standard.set(password, forKey: "password")', SWIFT_DEFAULTS,
       SWIFT_DEFAULTS_FIXED, "<<fn>>"),
    _t("sw-archive", "swift", "<<cls>>.swift", "CWE-502", "high",
       "Güvenilmeyen veri NSKeyedUnarchiver ile sınıf kısıtlaması olmadan çözülüyor",
       "unarchiveObject yerine unarchivedObject(ofClass:from:) kullan ve yalnızca beklenen sınıflara izin ver.",
       "NSKeyedUnarchiver.unarchiveObject(with: data)", SWIFT_ARCHIVE, SWIFT_ARCHIVE_FIXED, "<<fn>>"),

    _t("dk-root", "docker", "Dockerfile", "CWE-250", "medium",
       "Konteyner root kullanıcısıyla çalışıyor",
       "Ayrıcalıksız bir kullanıcı oluştur ve son USER yönergesini bu kullanıcıya ayarla.",
       "USER root", DOCKER_ROOT, DOCKER_ROOT_FIXED),
    _t("dk-env", "docker", "Dockerfile", "CWE-798", "high",
       "Parola imaj içine ENV ile gömülü",
       "Sırrı imaja yazma; çalışma anında ortam/secret yöneticisiyle ver ve açığa çıkan parolayı değiştir.",
       'ENV DB_PASSWORD="<<secret>>"', DOCKER_ENV, DOCKER_ENV_FIXED),
    _t("dk-curl", "docker", "Dockerfile", "CWE-494", "medium",
       "Uzak betik bütünlük doğrulaması olmadan indirilip çalıştırılıyor",
       "Betiği depoya al veya sürümlenmiş bir paketten kur ve çalıştırmadan önce SHA-256 özetini doğrula.",
       "curl -sSL https://get.example.com/install.sh | sh", DOCKER_CURL, DOCKER_CURL_FIXED),
    _t("dk-chmod", "docker", "Dockerfile", "CWE-732", "medium",
       "Uygulama dizini herkese yazılabilir (777)",
       "Dizinin sahibini uygulama kullanıcısı yap ve izinleri en az yetkiyle (u=rwX,g=rX,o=) ver.",
       "RUN chmod -R 777 /app", DOCKER_CHMOD, DOCKER_CHMOD_FIXED),

    _t("tf-ssh", "terraform", "main.tf", "CWE-284", "high",
       "Güvenlik grubu SSH'ı tüm internete (0.0.0.0/0) açıyor",
       "cidr_blocks değerini yönetim ağıyla sınırla (var.admin_cidr) veya SSH yerine oturum yöneticisi kullan.",
       'cidr_blocks = ["0.0.0.0/0"]', TF_SSH, TF_SSH_FIXED, None,
       TF_ALB_FP, 'cidr_blocks = ["0.0.0.0/0"]',
       "Bu grup herkese açık HTTPS (443) yük dengeleyici içindir; internetten erişim tasarım gereğidir."),
    _t("tf-ebs", "terraform", "main.tf", "CWE-311", "medium",
       "EBS diski şifrelenmemiş",
       "encrypted = true yap ve müşteri yönetimli bir KMS anahtarı (kms_key_id) belirt.",
       "encrypted         = false", TF_EBS, TF_EBS_FIXED),
    _t("tf-s3", "terraform", "main.tf", "CWE-668", "high",
       "S3 kovası public-read ACL ile herkese açık",
       "ACL'yi kaldır ve aws_s3_bucket_public_access_block ile tüm genel erişimi engelle.",
       'acl    = "public-read"', TF_S3, TF_S3_FIXED, None,
       TF_S3_FP, 'acl    = "public-read"',
       "Kova yalnızca herkese açık statik web sitesi varlıklarını barındırıyor; hassas veri yok, genel okuma tasarım gereğidir (gerekçeli istisna)."),
    _t("tf-dbpw", "terraform", "main.tf", "CWE-798", "high",
       "Veritabanı parolası Terraform koduna gömülü",
       "Parolayı sensitive bir değişkenle veya secret yöneticisiyle ver; koddaki parolayı değiştir.",
       'password          = "<<secret>>"', TF_DBPW, TF_DBPW_FIXED),

    _t("k8s-priv", "kubernetes", "pod.yaml", "CWE-250", "high",
       "Konteyner ayrıcalıklı (privileged) modda çalışıyor",
       "privileged: false yap; runAsNonRoot, allowPrivilegeEscalation: false ve capabilities drop ALL ile sertleştir.",
       "privileged: true", K8S_PRIV, K8S_FIXED, None,
       K8S_PRIV_FP, "privileged: true",
       "Bu bir CSI düğüm eklentisi (csi-system); birim bağlamak için ayrıcalıklı mod tasarım gereğidir (gerekçeli istisna)."),
    _t("k8s-root", "kubernetes", "pod.yaml", "CWE-250", "medium",
       "Konteyner root kullanıcısıyla (UID 0) çalışıyor",
       "runAsNonRoot: true ve sıfırdan farklı bir runAsUser ayarla.",
       "runAsUser: 0", K8S_ROOT, K8S_FIXED),
    _t("k8s-hostnet", "kubernetes", "pod.yaml", "CWE-668", "medium",
       "Pod ana makine ağını (hostNetwork) paylaşıyor",
       "hostNetwork'ü kaldır; gerekli portlar için Service/NodePort kullan.",
       "hostNetwork: true", K8S_HOSTNET, K8S_FIXED, None,
       K8S_HOSTNET_FP, "hostNetwork: true",
       "Bu bir node-exporter izleme ajanıdır; düğüm ağı metriklerini okuması için hostNetwork tasarım gereğidir."),
    _t("k8s-secret", "kubernetes", "pod.yaml", "CWE-798", "high",
       "Parola manifestte düz metin env değeri olarak yazılı",
       "Değeri Secret nesnesine taşı ve secretKeyRef ile oku; açığa çıkan parolayı değiştir.",
       'value: "<<secret>>"', K8S_SECRET, K8S_SECRET_FIXED),
    _t("k8s-sock", "kubernetes", "pod.yaml", "CWE-250", "high",
       "Docker soketi (docker.sock) pod'a bağlanmış",
       "docker.sock bağlamasını kaldır; gerekiyorsa rootless/izole bir derleme aracı (Kaniko vb.) kullan.",
       "path: /var/run/docker.sock", K8S_SOCK, K8S_FIXED),
    _t("k8s-hostpath", "kubernetes", "pod.yaml", "CWE-668", "high",
       "Ana makinenin kök dizini (/) pod'a yazılabilir bağlanmış",
       "hostPath yerine emptyDir/PVC kullan; ana makine dosyası gerçekten gerekiyorsa yalnızca dar bir dizini readOnly bağla.",
       "path: /", K8S_HOSTPATH, K8S_HOSTPATH_FIXED, None,
       K8S_HOSTPATH_FP, "path: /var/log",
       "Log toplayıcı yalnızca /var/log dizinini salt okunur (readOnly) bağlıyor; erişim dar ve tasarım gereğidir (gerekçeli istisna)."),
)
