# Configuration globale : logging et chargement des variables d'environnement
import logging
from dotenv import load_dotenv

load_dotenv()

# Configuration du système de logging : fichier + console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log", mode="a"),
        logging.StreamHandler(),
    ],
)

# Logger dédié au projet TP1
logger = logging.getLogger("TP1")
