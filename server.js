require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const upload = multer({ dest: "uploads/" });

app.get("/", (req, res) => {
  res.send("Servidor funcionando!");
});

app.post("/scan", upload.single("file"), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: "No se ha subido ningún archivo" });
    }

    const response = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: {
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
      },
      body: file.buffer,
    });

    const result = await response.json();
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al analizar el archivo" });
  }
});

app.get("/analysis/:id", async (req, res) => {
  try {
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${req.params.id}`,
      {
        headers: { "x-apikey": VIRUSTOTAL_API_KEY },
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
