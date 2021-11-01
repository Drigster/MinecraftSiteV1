import os.path
from PIL import Image
from sweater import app
from datetime import datetime

class Skin:
    def __init__(self, image, name):
        self.image = image
        self.name = name
    def save(self):
        skin = Image.open(self.image).convert("RGBA")
        template = Image.new("RGBA", (16, 32))

        head = skin.crop((8, 8, 16, 16))
        torso = skin.crop((20, 20, 28, 32))
        lHand = skin.crop((44, 20, 48, 32))
        rHand = skin.crop((36, 52, 40, 64))
        lLeg = skin.crop((4, 20, 8, 32))
        rLeg = skin.crop((20, 52, 24, 64))

        headL2 = skin.crop((40, 8, 48, 16))
        torsoL2 = skin.crop((20, 36, 28, 48))
        lHandL2 = skin.crop((52, 52, 56, 64))
        rHandL2 = skin.crop((44, 36, 48, 48))
        lLegL2 = skin.crop((4, 52, 8, 64))
        rLegL2 = skin.crop((4, 36, 8, 48))

        template.paste(head, (4, 0))
        template.paste(lHand, (0, 8))
        template.paste(torso, (4, 8))
        template.paste(rHand, (12, 8))
        template.paste(lLeg, (4, 20))
        template.paste(rLeg, (8, 20))

        template.paste(headL2, (4, 0), headL2)
        template.paste(lHandL2, (0, 8), lHandL2)
        template.paste(torsoL2, (4, 8), torsoL2)
        template.paste(rHandL2, (12, 8), rHandL2)
        template.paste(lLegL2, (4, 20), lLegL2)
        template.paste(rLegL2, (8, 20), rLegL2)

        skin.save(f"{app.config['UPLOADED_SKINS_DEST']}/{self.name}.png")
        template.resize((128, 256), 4).save(f"{app.config['UPLOADED_SKINS_DEST']}/{self.name}_body.png")
        head.resize((128, 128), 4).save(f"{app.config['UPLOADED_SKINS_DEST']}/{self.name}_head.png")

class Log:
    def __init__(self):
        time_now = datetime.now().strftime("%d.%m.%y")
        self.destination = f"{app.config['LOGS_DEST']}/{time_now}.txt"
        if not os.path.isfile(self.destination):
            with open(self.destination, 'w') as f:
                f.write(f'Log file created - {datetime.now().strftime("%d.%m.%y:%H.%M")}\n')

    def log(self, message):
        time_now = datetime.now().strftime("%d.%m.%y:%H.%M")
        with open(self.destination, 'a') as f:
            f.write(f'[{time_now}] {message}\n')
        