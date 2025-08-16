import prisma from "../../config/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET as string;
const JWT_EXPIRES_IN = "15m";

type SafeUser = {
  id: number;
  email: string;
  name: string | null;
  role: string;
  createdAt: Date;
  updatedAt: Date;
};

const toSafeUser = (u: any): SafeUser => {
  const { password: _pw, ...rest } = u;
  return rest as SafeUser;
};

export async function registerUser(params: {
  email: string;
  password: string;
  name?: string;
}): Promise<{ user: SafeUser; token: string }> {
  const { email, password, name } = params;

  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) throw new Error("Email already in use");

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: { email, password: hashedPassword, name },
  });

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    {
      expiresIn: JWT_EXPIRES_IN,
    }
  );

  return { user: toSafeUser(user), token };
}

export async function loginUser(params: {
  email: string;
  password: string;
}): Promise<{ user: SafeUser; token: string }> {
  const { email, password } = params;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("Invalid email or password");

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) throw new Error("Invalid email or password");

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    {
      expiresIn: JWT_EXPIRES_IN,
    }
  );

  return { user: toSafeUser(user), token };
}
