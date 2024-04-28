import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessTokenRefreshToken = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();   

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false});
        
        return {accessToken, refreshToken}
        
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

const registerUser = asyncHandler(async(req,res)=>{

    const {username, email, fullName, password} = req.body
    if([username, email, fullName, password].some(field=>field?.trim()==="")) throw new ApiError(401, "All fields are required")

    const existedUser = await User.findOne({
        $or: [{username}, {email} ]
    })

    if(existedUser) throw new ApiError(409, "User already exists.")

    const avatarLocalPath = req.files?.avatar[0]?.path
    const coverImageLocalPath = req.files?.coverImage[0]?.path

    console.log("MULTER REQ: ", req.files);

    if(!avatarLocalPath) throw new ApiError(400,"Local Avatar file is required")
    console.log("Avatar local Path: ", avatarLocalPath);

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    console.log("Avatar Cloudinary: ", avatar);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar) throw new ApiError(400,"Avatar file is required")

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        username: username.toLowerCase( ),
        email,
        password
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    if(!createdUser) throw new ApiError(500, "Something went wrong while registering the user.")

    return res.status(200).json(
        new ApiResponse(200, createdUser, "User registered.")
    )
})



const loginUser = asyncHandler(async(req,res)=>{
    try {
        const {username, email, password} = req.body
        if(!username && !email) throw new ApiError(402, "Username or Email is required.")
        const user = await User.findOne({
            $or : [{username},{email}]
        })
        if(!user) throw ApiError(401, "User does not exist.")
        
        const passwordValidation = await user.isPasswordCorrect(password)
        if(!passwordValidation) throw new ApiError(402, "Wrong credentials.")
    
        const {accessToken, refreshToken} = await generateAccessTokenRefreshToken(user._id)
    
        const logedInUser = await User.findById(user._id).select("-password -refreshToken")
        
        const options = {
            httpOnly : true,
            secure: true
        }
    
        return res
        .status(200)
        .cookie("accessToken",accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: logedInUser, accessToken, refreshToken
                },
                "User loged in successfully."
                )
        )    
    } catch (error) {
        throw new ApiError(400, "Wrong login credentials.")
    }
    
})

const logoutUser = asyncHandler(async(req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = { 
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully."))
})

const refreshAccessToken = asyncHandler(async(req,res)=>{
    try {
        const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken
        if(!incomingRefreshToken) throw new ApiError(401, "Unauthorized request.")

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        // if(!decodedToken) throw new ApiError(401, "Token mismatched.")

        const user = await User.findById(decodedToken?._id);
        if(!user) throw new ApiError(401, "Invalid refresh token.")

        if(incomingRefreshToken!==user.refreshToken) throw new ApiError(401, "Refresh token is expired or used.");

        const options = {
            httpOnly: true,
            secure: true
        }

        const {accessToken, refreshToken} = await generateAccessTokenRefreshToken(user._id);

        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(new ApiResponse(200,{accessToken,refreshToken},"Access token refreshed."))  
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken
}