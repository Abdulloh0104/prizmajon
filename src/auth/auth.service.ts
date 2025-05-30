import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { PrismaService } from "../prisma/prisma.service";
import { CreateUserDto } from "../users/dto";
import * as bcrypt from "bcrypt";
import { SignInDto } from "../users/dto/sign-in.dto";
import { Response } from "express";
import { User } from "../../generated/prisma";

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService
  ) {}

  async singUp(createUserDto: CreateUserDto, res: Response) {
    const { password, confirm_password, email, name } = createUserDto;
    const condidate = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (condidate) {
      throw new ConflictException("Bunday email mavjud");
    }
    if (password !== confirm_password) {
      throw new BadRequestException("Parollar mos emas");
    }

    const hashed_password = await bcrypt.hash(password, 7);
    const user = await this.prismaService.user.create({
      data: { name, email, hashed_password },
    });

    const tokens = await this.generateTokens(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);
    await this.updateRefreshToken(user.id, hashed_refresh_token);
    res.cookie("refreshToken", tokens.refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    return {
      message: "New User signed up",
      accessToken: tokens.accessToken,
    };
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    await this.prismaService.user.update({
      where: { id: userId },
      data: {
        hashed_refresh_token: refreshToken,
      },
    });
  }

  async generateTokens(admin: User) {
    const payload = {
      id: admin.id,
      is_active: admin.is_active,
      //   is_creator: admin.is_creator,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  }

  async singIn(signInDto: SignInDto, res: Response) {
    const { password, email} = signInDto
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (!user) {
      throw new ConflictException("Email yoki parol notog'ri");
    }

    const passwordMatch = await bcrypt.compare(password,user.hashed_password) 
    
    
    if (!passwordMatch) {
      throw new ConflictException("Email yoki parol notog'ri");
    }

    const tokens = await this.generateTokens(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);
    await this.updateRefreshToken(user.id, hashed_refresh_token);
    res.cookie("refreshToken", tokens.refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    return {
      message: "New User signed in",
      accessToken: tokens.accessToken,
    };
  }
  

    async signOut(refreshToken: string, res: Response) {
      const userData = await this.jwtService.verify(refreshToken, {
        secret: process.env.REFRESH_TOKEN_KEY,
      });
      if (!userData) {
        throw new ForbiddenException("Admin not verified");
      }

      const hashed_refresh_token = null;
      await this.updateRefreshToken(
        userData.id,
        hashed_refresh_token!
      );

      res.clearCookie("refreshToken");
      const response = {
        message: "User logged out seccessfully",
      };
      return response;
    }

    async refreshToken(userId: number, refresh_token: string, res: Response) {
      const decodedToken = await this.jwtService.decode(refresh_token);
      // console.log(userId);
      // console.log(decodedToken["id"]);

      if (userId !== decodedToken["id"]) {
        throw new ForbiddenException("Ruxsat etilmagan");
      }
      const user = await this.prismaService.user.findUnique({where:{id:Number(userId)}});

      if (!user || !user.hashed_refresh_token) {
        throw new NotFoundException("user not found");
      }

      const tokenMatch = await bcrypt.compare(
        refresh_token,
        user.hashed_refresh_token
      );
      if (!tokenMatch) {
        throw new ForbiddenException("Forbidden");
      }

      const { accessToken, refreshToken } = await this.generateTokens(user);

      const hashed_refresh_token = await bcrypt.hash(refreshToken, 7);
      await this.updateRefreshToken(user.id, hashed_refresh_token);

      res.cookie("refreshToken", refreshToken, {
        maxAge: Number(process.env.COOKIE_TIME),
        httpOnly: true,
      });

      const response = {
        message: "User refreshed",
        userId: user.id,
        access_token: accessToken,
      };
      return response;
    }
}
