# Utilisez une image officielle de Node.js, version 16
FROM node:16

# Définissez le répertoire de travail
WORKDIR /usr/src/app

# Copiez le fichier package.json et package-lock.json
COPY package*.json ./

# Installez les dépendances
RUN npm install

# Installez Nodemon globalement
RUN npm install -g nodemon

# Copiez le reste de l'application
COPY . .

# Exposez le port que votre application utilise
EXPOSE 3000

# Commande pour démarrer l'application avec Nodemon
CMD ["nodemon", "app.js"]