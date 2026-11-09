import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
const prisma = new PrismaClient();
const SECRET_KEY = "mi_clave_super_secreta_b2b"; 

app.use(express.json());
export interface AuthRequest extends Request {
  user?: any;
}

const verificarToken = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const token = req.headers.authorization?.split(" ")[1]; 
  
  if (!token) {
    res.status(401).json({ error: "Acceso denegado. Token no proporcionado." });
    return;
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; 
    next(); 
  } catch (error) {
    res.status(403).json({ error: "Token inválido o expirado." });
  }
};

const soloAdmin = (req: AuthRequest, res: Response, next: NextFunction): void => {
  if (req.user?.role !== 'ADMIN') {
    res.status(403).json({ error: "Acceso denegado. Se requiere rol de ADMIN." });
    return;
  }
  next();
};

app.post('/api/users', async (req, res) => {
  try {
    const { email, password, companyName, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = await prisma.user.create({
      data: { email, password: hashedPassword, companyName, role: role || 'CLIENT' }
    });
    res.status(201).json({ message: "Usuario creado exitosamente", id: newUser.id, role: newUser.role });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear la empresa' });
  }
});

app.post('/api/login', async (req, res): Promise<any> => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(401).json({ error: "Contraseña incorrecta" });
  const token = jwt.sign(
    { id: user.id, role: user.role, company: user.companyName }, 
    SECRET_KEY, 
    { expiresIn: '2h' }
  );
  
  res.json({ message: "Login exitoso", token, role: user.role });
});

app.post('/api/products', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { sku, name, price, stock, minStock } = req.body;
    const newProduct = await prisma.product.create({
      data: { sku, name, price, stock, minStock }
    });
    res.status(201).json({ message: "Producto creado", product: newProduct });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear el producto' });
  }
});

app.get('/api/products', verificarToken, async (req, res) => {
  const products = await prisma.product.findMany();
  res.json(products);
});

app.post('/api/orders', verificarToken, async (req: AuthRequest, res) => {
  try {
    const userId = req.user.id; 
    const { items } = req.body; 

    const result = await prisma.$transaction(async (tx) => {
      let total = 0;
      const orderItemsData = [];

      for (const item of items) {
        const product = await tx.product.findUnique({ where: { id: item.productId } });
        if (!product) throw new Error(`Producto no encontrado.`);
        if (product.stock < item.quantity) {
          throw new Error(`Stock insuficiente para ${product.name}.`);
        }

        total += Number(product.price) * item.quantity;

        await tx.product.update({
          where: { id: item.productId },
          data: { stock: product.stock - item.quantity }
        });

        orderItemsData.push({
          productId: item.productId,
          quantity: item.quantity,
          unitPrice: product.price
        });
      }

      return await tx.order.create({
        data: {
          userId,
          total,
          status: 'PENDIENTE',
          items: { create: orderItemsData }
        },
        include: { items: true }
      });
    });

    res.status(201).json({ message: "Orden procesada con éxito", order: result });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor Seguro B2B corriendo en http://localhost:${PORT}`);
});