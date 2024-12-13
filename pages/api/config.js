export default function handler(req, res) {
    res.setHeader('Content-Type', 'application/json');
    const clientConfig = {
      API_ENDPOINTS: {
        TRUST_POSITIF: 'https://api.trustpositif.app',
        KLIKLI: 'https://klikli.ink/api',
        PROXY: 'http://localhost:3001'
      },
    };
    res.status(200).json(clientConfig);
  }
