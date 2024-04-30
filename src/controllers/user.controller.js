import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

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

const updateAvatar = asyncHandler(async(req, res)=>{
    try {
    
        const avatarLocalPath = req.file?.path
        if(!avatarLocalPath) throw new ApiError(401, "Invalid avatar.")
    
        const avatar = await uploadOnCloudinary(avatarLocalPath)
        if(!avatar) throw new ApiError(500, "Cloudinary failed. Please try again.") 

        // req.user.avatar = avatarPath
        const user = await User.findByIdAndUpdate(req.user._id,{
            $set: {
                "avatar": avatar.url
            }
        },
        {
            new: true
        }
        ).select("-password")

        return res
        .status(200)
        .json(
            new ApiResponse(200,user, "Avatar updated successfully.")
        )
        
    } catch (error) {
        throw new ApiError(error?.status || 401, "Avatar file required.")
    }

})
const updateCoverImage = asyncHandler(async(req, res)=>{
    try {
    
        const coverImageLocalPath = req.file?.path
        if(!coverImageLocalPath) throw new ApiError(401, "Invalid avatar.")
    
        const coverImage = await uploadOnCloudinary(coverImageLocalPath)
        if(!coverImage) throw new ApiError(500, "Cloudinary failed. Please try again.") 

        // req.user.avatar = avatarPath
        const user = await User.findByIdAndUpdate(req.user._id,{
            $set: {
                "avatar": coverImage.url
            }
        },
        {
            new: true
        }
        ).select("-password")

        return res
        .status(200)
        .json(
            new ApiResponse(200,user, "Avatar updated successfully.")
        )
        
    } catch (error) {
        throw new ApiError(error?.status || 401, "Avatar file required.")
    }

})

const updatePassword = asyncHandler(async(req,res)=>{
    try {
        
        const {oldPassword, newPassword} = req.body;
        
        if(!oldPassword || !newPassword) throw new ApiError(401, "Old and New Passwords are needed.")

        if(oldPassword===newPassword) throw new ApiError(401, "Passwords cannot be same.")
        
        const user = await User.findById(req.user?._id)
        
        const oldPasswordValidation = user.isPasswordCorrect(oldPassword)
        if(!oldPasswordValidation) throw new ApiError(400, "Old Password is incorrect")
        
        user.password = newPassword
        await user.save({validateBeforeSave: false})

        return res.
        status(200)
        .json(200,{},"Password updated successfully.")

    } catch (error) {
        throw new ApiError(400, "Error caught in catch of updatePassword.")
    }

})

const updateUserNameAndFullName = asyncHandler(async(req, res)=>{
    // const user = await User.findById(req.user._id)
    // const {username, fullName} = user

    try {
        const {updatedUserName, updatedFullName} = req.body
        if(!updatedUserName || !updatedFullName) throw new ApiError("Naming fields required.")
    
        const updatedFields = {}
    
        if(updatedUserName) updatedFields.username = updatedUserName
        if(updatedFullName) updatedFields.fullName = updatedFullName
        
    
        const user = await User.findByIdAndUpdate(req?.user?._id,{
            $set:{ updatedFields}
        },
        {
            new: true
        }).select("-password")

        if (!user) {
            throw new ApiError(404, "User not found.");
        }
    
        // await user.save({"validateBeforeSave": false})
    
        return res
        .status(200)
        .json(new ApiResponse(200,user,"Fields updated successfully"))
        
    } catch (error) {
        throw new ApiError(400, "Error caught in catch of updateUserNameAndFullName")
    }

})

const getUserChannelProfile = asyncHandler(async(req,res)=>{
    const {username} = req.params
    const channel = await User.aggregate([
        {
            $match: {
                username : username.toLowerCase()
            }
        },
        { 
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        { 
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount : { $size: "$subscribers" },
                channelFieldCount : { $size: "$subscribedTo"},
                isSubscribed:{
                    $cond:{
                        if: {$in: [req.user?._id, "$subscribers.subscribers"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project:{
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelFieldCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if(!channel?.length) throw new ApiResponse(404, "Channel does not exist.")

    return res
    .status(200)
    .json(new ApiResponse(200, channel[0], "Channel data fetched successfully."))
})

const getWatchHistory = asyncHandler(async (req,res)=>{
    const user = await User.aggregate([
        {
            $match: {
                // _id: new mongoose.Types.ObjectId(req.user._id) // new mongoose.Types.ObjectId(req.user._id) got deprecated.
                _id: new mongoose.Types.ObjectId.createFromHexString(req.user._id)
            }
        },
        {
            $lookup:{
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup : {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline :[{
                                $project: {
                                    fullName: 1,
                                    username: 1,
                                    avatar: 1
                                }
                            }]
                        }
                    },
                    {
                        $addFields: {
                            owner: { $first: "$owner"}
                        }
                    }
                ]
            }
        }
    ])

    return res
    .status(200)
    .json( new ApiResponse(200, user[0].watchHistory,"Watch history fetched successfully."))
})



export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    updateAvatar,
    updatePassword,
    updateCoverImage,
    updateUserNameAndFullName,
    getUserChannelProfile,
    getWatchHistory
}