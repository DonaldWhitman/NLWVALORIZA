import { getCustomRepository } from "typeorm";
import { compare } from "bcryptjs"
import { sign } from "jsonwebtoken"
import { UsersRepositories } from "../repositories/UsersRepositories";

interface IAuthenticateRequest {
  email: string;
  password: string;
}

class AuthenticateUserService {
  
  async execute({ email, password}: IAuthenticateRequest) {
    const usersRepositories = getCustomRepository(UsersRepositories);

    const user = await usersRepositories.findOne({
      email
    });

    if(!user) {
      throw new Error("Incorret email/password")
    }

    const passwordMatch = await compare(password, user.password);

    if(!passwordMatch) {
      throw new Error("Incorret email/password")
    }

    const token = sign(
      {
      email: user.email
      }, 
      "7b443f612aab5a14d6aa82d412398a1b", 
      {
        subject : user.id, 
        expiresIn: "1d"
      }
    );

    return token;
  }
}

export { AuthenticateUserService };