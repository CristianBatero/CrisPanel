const fs = require('fs');
const path = require('path');
require('dotenv').config();

console.log("=== Diagnóstico de Persistencia Local ===");

// 1. Verificar Variables de Entorno
console.log("\n1. Verificando Variables de Entorno (.env)...");
if (fs.existsSync(path.join(__dirname, '.env'))) {
    console.log("✅ Archivo .env encontrado.");
} else {
    console.warn("⚠️  Archivo .env NO encontrado. Se recomienda usarlo para persistencia local.");
}

if (process.env.GITHUB_TOKEN) {
    console.log("✅ GITHUB_TOKEN encontrada. Se usará GitHub para guardar config.json y usuarios.");
} else {
    console.warn("⚠️  GITHUB_TOKEN no configurada.");
    console.log("   Si tu servidor remoto se reinicia y pierdes la API Key o usuarios, NECESITAS configurar esto.");
    console.log("   Variables requeridas: GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO");
}

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.log("✅ FIREBASE_SERVICE_ACCOUNT está configurada en el entorno.");
    try {
        const creds = JSON.parse(Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT, 'base64').toString('utf8'));
        console.log(`   Proyecto Firebase: ${creds.project_id}`);
        console.log("   Esta es la configuración recomendada para persistencia permanente.");
    } catch (e) {
        console.error("❌ Error al decodificar FIREBASE_SERVICE_ACCOUNT:", e.message);
    }
} else {
    console.warn("⚠️  FIREBASE_SERVICE_ACCOUNT no está configurada.");
    console.log("   Para solucionar esto permanentemente:");
    console.log("   1. Coloca tu archivo 'service-account.json' en esta carpeta.");
    console.log("   2. Ejecuta: node setup_firebase.js service-account.json");
}

// 2. Verificar Archivos de Datos Locales
console.log("\n2. Verificando Datos Locales (FileStorage)...");
const dataDir = path.join(__dirname, 'data');
if (fs.existsSync(dataDir)) {
    console.log(`✅ Directorio 'data' existe en: ${dataDir}`);
    
    const configPath = path.join(dataDir, 'config.json');
    if (fs.existsSync(configPath)) {
        console.log("✅ config.json encontrado.");
        try {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            if (config.ApiKey) {
                console.log("   API Key guardada: SI");
            } else {
                console.warn("⚠️  API Key no encontrada en config.json.");
            }
        } catch (e) {
            console.error("❌ Error leyendo config.json:", e.message);
        }
    } else {
        console.warn("⚠️  config.json no existe. Se creará al guardar configuraciones.");
    }

    const saPath = path.join(dataDir, 'service-account.json');
    if (fs.existsSync(saPath)) {
        console.log("✅ service-account.json encontrado en 'data'.");
        console.warn("⚠️  Advertencia: Este archivo puede perderse si el servidor remoto se reinicia y no usa almacenamiento persistente.");
    } else {
        console.log("ℹ️  service-account.json no está en 'data'. (Correcto si usas Variables de Entorno)");
    }

} else {
    console.warn("⚠️  Directorio 'data' no existe. Se creará al iniciar el servidor.");
}

// 3. Recomendación Final
console.log("\n=== Conclusión ===");
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.log("✅ Tu configuración local es ROBUSTA. La variable de entorno asegura que Firebase funcione siempre.");
    console.log("   Para el servidor remoto (Panel), asegúrate de copiar el contenido de FIREBASE_SERVICE_ACCOUNT de tu .env");
    console.log("   a las variables de entorno de tu proveedor de hosting (Netlify, Heroku, Railway, etc.).");
} else {
    console.log("❌ Tu configuración es VULNERABLE a reinicios.");
    console.log("   Por favor, ejecuta el script de configuración de Firebase para asegurar la persistencia.");
}
