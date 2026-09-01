const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// NetSentinel Siber Güvenlik Kuralları
const SECURITY_RULES = [
    { id: "CRYPTO_MINER", name: "Kripto Madencilik Betiği", pattern: /(coinhive|cryptoloot|cnhv\.co|coin-hive|webminer|monerominer)/i, weight: 40, type: "TEHLİKE" },
    { id: "OBFUSCATED_CODE", name: "Şifrelenmiş/Gizlenmiş JavaScript", pattern: /(eval\s*\(\s*function|unescape\s*\(|atob\s*\(|String\.fromCharCode)/i, weight: 20, type: "ŞÜPHE" },
    { id: "KEYLOGGER", name: "Veri Çalma / Keylogger İmzası", pattern: /(addEventListener\s*\(\s*['"]keydown['"]|onkeydown\s*=|document\.cookie)/i, weight: 35, type: "TEHLİKE" },
    { id: "HIDDEN_IFRAME", name: "Gizli Çerçeve (Hidden Iframe)", pattern: /<iframe[^>]*style=["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)[^"']*["']/gi, weight: 25, type: "ŞÜPHE" },
    { id: "SUSPICIOUS_REDIRECT", name: "Otomatik Yönlendirme Tuzağı", pattern: /(window\.location\.href\s*=|location\.replace\s*\()/i, weight: 15, type: "BİLGİ" }
];

app.get('/api/scan', async (req, res) => {
    let { url } = req.query;

    if (!url) {
        return res.status(400).json({ error: "Lütfen geçerli bir URL adresi sağlayın." });
    }

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    const startTime = Date.now();
    
    const scanResult = {
        projectName: "NetSentinel v2.0",
        targetUrl: url,
        timestamp: new Date().toLocaleString('tr-TR'),
        securityScore: 100, // Başlangıç skoru 100
        status: "GÜVENLİ",
        detectedThreats: [],
        metrics: {
            responseTimeMs: 0,
            isHttps: url.startsWith('https://'),
            htmlSizeKb: 0,
            scriptCount: 0,
            linkCount: 0
        }
    };

    try {
        const response = await axios.get(url, {
            timeout: 8000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetSentinel-Security-Scanner/2.0'
            }
        });

        scanResult.metrics.responseTimeMs = Date.now() - startTime;
        
        const html = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        scanResult.metrics.htmlSizeKb = (html.length / 1024).toFixed(2);

        // Script ve Link Sayıları
        const scriptMatches = html.match(/<script/gi);
        const linkMatches = html.match(/<a/gi);
        scanResult.metrics.scriptCount = scriptMatches ? scriptMatches.length : 0;
        scanResult.metrics.linkCount = linkMatches ? linkMatches.length : 0;

        // HTTP/HTTPS Puan Kırma
        if (!scanResult.metrics.isHttps) {
            scanResult.securityScore -= 15;
            scanResult.detectedThreats.push({
                threatName: "Güvensiz Bağlantı (HTTP)",
                severity: "ORTA",
                desc: "Site HTTPS şifreleme sertifikası kullanmıyor."
            });
        }

        // Güvenlik Kuralları Taraması
        SECURITY_RULES.forEach(rule => {
            if (rule.pattern.test(html)) {
                scanResult.securityScore -= rule.weight;
                scanResult.detectedThreats.push({
                    threatName: rule.name,
                    severity: rule.weight >= 30 ? "YÜKSEK" : "ORTA",
                    desc: `Sitede ${rule.type} kategorisine giren kod deseni tespit edildi.`
                });
            }
        });

        // Skor Hesaplama ve Durum Belirleme
        if (scanResult.securityScore < 0) scanResult.securityScore = 0;

        if (scanResult.securityScore >= 85) {
            scanResult.status = "GÜVENLİ (A+)";
        } else if (scanResult.securityScore >= 60) {
            scanResult.status = "ORTA RİSK (B)";
        } else {
            scanResult.status = "YÜKSEK TEHLİKE (F)";
        }

        return res.json(scanResult);

    } catch (error) {
        return res.status(500).json({
            error: "Hedef siteye erişilemedi veya site yanıt vermiyor.",
            details: error.message
        });
    }
});

app.listen(PORT, () => {
    console.log(`===========================================`);
    console.log(`🛡️  NETSENTINEL GÜVENLİK SUNUCUSU AKTİF!`);
    console.log(`🔗 Web Arayüzü İçin: index.html dosyasını açın.`);
    console.log(`===========================================`);
});