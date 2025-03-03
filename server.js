require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const axios = require("axios");
const FormData = require("form-data");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ storage: multer.memoryStorage() });

app.get("/", (req, res) => {
  res.send("Servidor funcionando!");
});

app.post("/verify-recaptcha", async (req, res) => {
  console.log("Se intenta verificar el CAPTCHA");
  const { token } = req.body;
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;

  if (!token) {
    console.log("No hay token");
    return res.status(400).json({ success: false, error: "Token no recibido" });
  }

  try {
    const response = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `secret=${secretKey}&response=${token}`,
      }
    );

    const data = await response.json();

    if (data.success) {
      return res.json({ success: true, score: data.score });
    } else {
      console.log("Error en la validación de Google:", data["error-codes"]);
      return res
        .status(400)
        .json({ success: false, error: data["error-codes"] });
    }
  } catch (error) {
    console.error("Error al conectar con Google ReCAPTCHA:", error);
    return res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

app.post("/scan", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No se ha subido ningún archivo" });
    }

    console.log("Archivo recibido en backend:", {
      fieldname: req.file.fieldname,
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
    });

    const formData = new FormData();
    formData.append("file", req.file.buffer, req.file.originalname);

    console.log("Enviando archivo a VirusTotal...");

    const response = await axios.post(
      "https://www.virustotal.com/api/v3/files",
      formData,
      {
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY,
          ...formData.getHeaders(),
        },
      }
    );

    console.log("Respuesta de VirusTotal:", response.data);
    res.json(response.data);
  } catch (error) {
    console.error(
      "Error al analizar el archivo:",
      error.response?.data || error.message
    );
    res.status(500).json({ error: "Error al analizar el archivo" });
  }
});

app.get("/analysis/:id", async (req, res) => {
  try {
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${req.params.id}`,
      {
        headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error(
      "Error al obtener reporte de VirusTotal:",
      error.response?.data || error.message
    );
    res.status(500).json({ error: "Error al obtener el análisis" });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor en ejecución en http://localhost:${PORT}`);
});
