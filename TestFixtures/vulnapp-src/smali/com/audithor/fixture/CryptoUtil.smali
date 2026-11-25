.class public Lcom/audithor/fixture/CryptoUtil;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static encrypt([B)[B
    .registers 6
    const-string v0, "DES/ECB/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
    const-string v2, "hardcodedkey1234"
    invoke-virtual {v2}, Ljava/lang/String;->getBytes()[B
    move-result-object v2
    const-string v3, "AES"
    invoke-direct {v1, v2, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    const/4 v2, 0x1
    invoke-virtual {v0, v2, v1}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V
    invoke-virtual {v0, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B
    move-result-object v0
    return-object v0
.end method

.method public static hash(Ljava/lang/String;)[B
    .registers 3
    const-string v0, "MD5"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v0
    invoke-virtual {p0}, Ljava/lang/String;->getBytes()[B
    move-result-object v1
    invoke-virtual {v0, v1}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v0
    return-object v0
.end method
