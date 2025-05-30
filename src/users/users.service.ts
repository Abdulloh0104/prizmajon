import { BadRequestException, Injectable } from "@nestjs/common";
import { CreateUserDto } from "./dto/create-user.dto";
import { PrismaService } from "../prisma/prisma.service";
import { UpdateUserDto } from "./dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class UsersService {
  constructor(private readonly prismaService: PrismaService) {}
  async create(createUserDto: CreateUserDto) {
    const { password, confirm_password,email,name } = createUserDto;
    if (password !== confirm_password) {
      throw new BadRequestException("Parollar mos emas");
    }

    const hashed_password = await bcrypt.hash(password, 7);
    return this.prismaService.user.create({
      data: { name,email, hashed_password },
    });
  }

  findAll() {
    return this.prismaService.user.findMany()
  }

  findOne(id: number) {
    return this.prismaService.user.findUnique({where:{id}})
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return this.prismaService.user.update({where:{id},data:updateUserDto})
  }

  remove(id: number) {
    return this.prismaService.user.delete({where:{id}})
  }
}
