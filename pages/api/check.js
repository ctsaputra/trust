   export default async function handler(req, res) {
     if (req.method === 'POST') {
       const { domain } = req.body;
       // Lakukan logika pengecekan domain di sini
       res.status(200).json({ status: 'success', domain });
     } else {
       res.status(405).json({ message: 'Method not allowed' });
     }
   }
