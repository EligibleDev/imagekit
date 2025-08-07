import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { ConnectToDB } from "./db";
import User from "@/models/User";
import bcrypt from "bcryptjs";

export const authOptions: NextAuthOptions = {
    providers: [
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "text" },
                password: { label: "Password", type: "password" },
            },
            async authorize(credentials) {
                if (!credentials?.email || !credentials?.password) {
                    throw new Error("Missing email or password");
                }

                try {
                    await ConnectToDB();

                    const user = await User.findOne({
                        email: credentials.email,
                    });

                    if (!user) {
                        throw new Error("Account doesn't exist");
                    }

                    const isValid = await bcrypt.compare(
                        credentials.password,
                        user.password
                    );

                    if (!isValid) {
                        throw new Error("Invalid credentials");
                    }

                    return {
                        id: user._id.toString(),
                        email: user.email,
                    };
                } catch (error) {
                    console.error("Login error", error);
                    throw error;
                }
            },
        }),
    ],
};
