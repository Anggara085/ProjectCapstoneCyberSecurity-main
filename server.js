const express = require('express');
const multer = require('multer');
const cryptoJS = require('crypto-js');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const https = require('https');
const cors = require('cors');

// Inisialisasi aplikasi Express
const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Konfigurasi JWT
const jwtSecret = 'SECRETNUMBER';
const generateJWT = () => jwt.sign({ user: 'anonymous' }, jwtSecret, { expiresIn: '1h' });
const verifyJWT = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('JWT token required');
  try {
    jwt.verify(token.split(' ')[1], jwtSecret);
    next();
  } catch {
    return res.status(403).send('Invalid JWT token');
  }
};

// Konfigurasi multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads');
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const filename = `${timestamp}-${file.originalname}`;
    cb(null, filename);
  },
});
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only image files are allowed!'));
  },
});
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

// Endpoint untuk mendapatkan JWT
app.get('/token', (req, res) => {
  const token = generateJWT();
  res.json({ token });
});

// Endpoint untuk enkripsi AES-128
app.post('/encryptaes128', verifyJWT, upload.single('file'), (req, res, next) => {
  try {
    const secretKey = req.body.secretKey;
    if (!secretKey || secretKey.length !== 16) return res.status(400).send('Secret key must be 16 characters long');
    if (!req.file) return res.status(400).send('No file uploaded or invalid file type');

    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    const imageData = fs.readFileSync(filePath);
    const base64Image = imageData.toString('base64');
    const encryptedData = cryptoJS.AES.encrypt(base64Image, secretKey).toString();

    const encryptedFilePath = path.join(__dirname, 'uploads', 'encrypted_image_aes128.txt');
    fs.writeFileSync(encryptedFilePath, encryptedData);
    res.download(encryptedFilePath, 'encrypted_image_aes128.txt', (err) => {
      if (err) console.error(err);
      fs.unlinkSync(filePath);
      fs.unlinkSync(encryptedFilePath);
    });
  } catch (error) {
    next(error);
  }
});

// Endpoint untuk dekripsi AES-128
app.post('/decryptaes128', verifyJWT, upload.single('file'), (req, res, next) => {
  try {
    const secretKey = req.body.secretKey;
    if (!secretKey || secretKey.length !== 16) return res.status(400).send('Secret key must be 16 characters long');
    if (!req.file) return res.status(400).send('No file uploaded or invalid file type');

    const encryptedFilePath = path.join(__dirname, 'uploads', req.file.filename);
    const encryptedData = fs.readFileSync(encryptedFilePath, 'utf8');
    const decryptedData = cryptoJS.AES.decrypt(encryptedData, secretKey).toString(cryptoJS.enc.Utf8);

    if (!decryptedData) return res.status(400).send('Decryption failed. Check your secret key or file.');

    const imageBuffer = Buffer.from(decryptedData, 'base64');
    const decryptedFilePath = path.join(__dirname, 'uploads', 'decrypted_image.jpg');
    fs.writeFileSync(decryptedFilePath, imageBuffer);
    res.download(decryptedFilePath, 'decrypted_image.jpg', (err) => {
      if (err) console.error(err);
      fs.unlinkSync(encryptedFilePath);
      fs.unlinkSync(decryptedFilePath);
    });
  } catch (error) {
    next(error);
  }
});

// Endpoint untuk enkripsi AES-256
app.post('/encrypt', verifyJWT, upload.single('file'), (req, res, next) => {
  try {
    const secretKey = req.body.secretKey;
    if (!secretKey || secretKey.length !== 32) return res.status(400).send('Secret key must be 32 characters long');
    if (!req.file) return res.status(400).send('No file uploaded or invalid file type');

    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    const imageData = fs.readFileSync(filePath);
    const base64Image = imageData.toString('base64');
    const encryptedData = cryptoJS.AES.encrypt(base64Image, secretKey).toString();

    const encryptedFilePath = path.join(__dirname, 'uploads', 'encrypted_image_aes256.txt');
    fs.writeFileSync(encryptedFilePath, encryptedData);
    res.download(encryptedFilePath, 'encrypted_image_aes256.txt', (err) => {
      if (err) console.error(err);
      fs.unlinkSync(filePath);
      fs.unlinkSync(encryptedFilePath);
    });
  } catch (error) {
    next(error);
  }
});

app.post('/decrypt', verifyJWT, (req, res) => {
  try {
    const { secretKey, encryptedData } = req.body;
    if (!secretKey || secretKey.length !== 32)
      return res.status(400).send('Secret key must be 32 characters long');
    if (!encryptedData)
      return res.status(400).send('No encrypted data provided');
    
    // Dekripsi data terenkripsi
    const decryptedData = cryptoJS.AES.decrypt(encryptedData, secretKey).toString(cryptoJS.enc.Utf8);
    if (!decryptedData)
      return res.status(400).send('Decryption failed. Check your secret key or file.');

    // Convert base64 decrypted data into image buffer
    const imageBuffer = Buffer.from(decryptedData, 'base64');

    // Tentukan path untuk file gambar yang didekripsi
    const decryptedFilePath = path.join(__dirname, 'uploads', 'decrypted_image.jpg');

    // Tulis buffer ke file gambar
    fs.writeFileSync(decryptedFilePath, imageBuffer);

    // Kirimkan file gambar ke client
    res.download(decryptedFilePath, 'decrypted_image.jpg', (err) => {
      if (err) console.error(err);
      fs.unlinkSync(decryptedFilePath); // Hapus file setelah dikirim
    });
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).send('An error occurred: ' + error.message);
  }
});


// Middleware untuk menangani error
app.use((err, req, res, next) => {
  console.error('Error middleware:', err.message);
  res.status(500).send('An error occurred: ' + err.message);
});

// Konfigurasi SSL
//const sslOptions = {
//  key: fs.readFileSync(path.join(__dirname, 'ssl', 'server.key')),
//  cert: fs.readFileSync(path.join(__dirname, 'ssl', 'server.crt')),
//};
//const httpsServer = https.createServer(sslOptions, app);

// Menjalankan server HTTPS
//httpsServer.listen(3000, () => {
//  console.log('Server started on https://localhost:3000');
//});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});