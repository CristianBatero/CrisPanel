const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);

if (args.length === 0) {
  console.log('Uso: node setup_firebase.js "ruta/al/archivo-firebase.json"');
  process.exit(1);
}

const filePath = args[0];

try {
  if (!fs.existsSync(filePath)) {
    console.error(`Error: El archivo "${filePath}" no existe.`);
    process.exit(1);
  }

  const content = fs.readFileSync(filePath, 'utf8');
  // Validar que sea JSON
  try {
    JSON.parse(content);
  } catch (e) {
    console.error('Error: El archivo no es un JSON válido.');
    process.exit(1);
  }

  const base64 = Buffer.from(content).toString('base64');
  
  const envPath = path.join(__dirname, '.env');
  let envContent = '';
  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, 'utf8');
  }

  // Si ya existe la variable, reemplazarla
  if (envContent.includes('FIREBASE_SERVICE_ACCOUNT=')) {
    envContent = envContent.replace(/FIREBASE_SERVICE_ACCOUNT=.*/, `FIREBASE_SERVICE_ACCOUNT=${base64}`);
  } else {
    envContent += `\nFIREBASE_SERVICE_ACCOUNT=${base64}\n`;
  }

  fs.writeFileSync(envPath, envContent, 'utf8');
  console.log('¡Éxito! La configuración de Firebase se ha guardado permanentemente en .env');
  console.log('Ahora puedes reiniciar el servidor y la conexión será estable.');

} catch (error) {
  console.error('Error inesperado:', error.message);
}
