.class public Lcom/audithor/fixture/MainActivity;
.super Landroid/app/Activity;

.field private static final AWS_KEY:Ljava/lang/String; = "AKIAIOSFODNN7EXAMPLE"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method public setupWebView(Landroid/webkit/WebView;)V
    .registers 6
    invoke-virtual {p1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v0
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
    new-instance v2, Ljava/lang/Object;
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V
    const-string v3, "Android"
    invoke-virtual {p1, v2, v3}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    invoke-static {v1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
    return-void
.end method

.method public saveToken(Ljava/lang/String;Ljava/lang/String;)V
    .registers 7
    const-string v0, "prefs"
    const/4 v1, 0x0
    invoke-virtual {p0, v0, v1}, Lcom/audithor/fixture/MainActivity;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    const-string v1, "auth_token"
    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V
    const-string v1, "Login"
    new-instance v2, Ljava/lang/StringBuilder;
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V
    const-string v3, "user password="
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v2
    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
    return-void
.end method
