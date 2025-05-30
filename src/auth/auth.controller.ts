import { Body, Controller, HttpCode, Param, Post, Res } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { CreateUserDto } from "../users/dto";
import { Response } from "express";
import { SignInDto } from "../users/dto/sign-in.dto";
import { CookieGetter } from "./common/decorators/cookie-getter.decorator";

@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("signup")
  async signup(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.singUp(createUserDto, res);
  }

  @HttpCode(200)
  @Post("signin")
  async signin(
    @Body() signInDto: SignInDto,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.singIn(signInDto, res);
  }

  @Post("signout")
  signout(
    @CookieGetter("refreshToken") refreshToken: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.signOut(refreshToken, res);
  }

  @Post(":id/refresh")
  refresh(
    @Param("id") id: string,
    @CookieGetter("refreshToken") refreshToken: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.refreshToken(+id, refreshToken, res);
  }
}
