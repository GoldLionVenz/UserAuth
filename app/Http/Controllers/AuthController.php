<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\User;
use App\Notifications\SignupActivate;
use Avatar;
use Storage;
class AuthController extends Controller
{
    
    public function signup(Request $request){

        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string'
        ]);

        $avatar;
        $avatarPath;
        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'activation_token' => str_random(60)
        ]);

        if($request->file){
            $avatar = str_replace('data:image/png;base64,','',$request->input('file')) ;
            $avatar = str_replace(' ', '+', $avatar);
            $avatarPath = 'avatars/'.str_random(40).'.'.'jpg';
            Storage::disk('public')->put($avatarPath, base64_decode($avatar));
        }else{
            $avatar=Avatar::create($request->name)->getImageObject()->encode('png');
            $avatarPath='avatars/'.str_random(20).'.png';
            Storage::disk('public')->put($avatarPath, (string) $avatar);
        }
        
        $user->avatar=Storage::url($avatarPath);
        $user->notify(new SignupActivate($user));
        $user->save();
        return response()->json([
            'message' => 'Successfully created user!'
        ], 201);
    }

    public function login(Request $request){
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);

        $credentials = request(['email', 'password']);
        $credentials['active'] = 1;
        $credentials['deleted_at'] = null;
        if(!Auth::attempt($credentials))
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        $user = $request->user();

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->remember_me)
            $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();
        return response()->json([
            'id'=>$user->id,
            'name'=>$user->name,
            'email'=>$user->email,
            'avatar'=>url($user->avatar),
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        ]);
    }

    public function logout(Request $request){
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }

    public function user(Request $request){
        $user=$request->user();
        return [
            'id'=>$user->id,
            'name'=>$user->name,
            'email'=>$user->email,
            'user_name'=>$user->user_name,
            'avatar'=>url($user->avatar) 
        ];
    }

    public function signupActivate($token){
        $user = User::where('activation_token', $token)->first();
        if (!$user) {
            return response()->json([
                'message' => 'This activation token is invalid.'
            ], 404);
        }
        $user->active = true;
        $user->activation_token = '';
        $user->save();
        return $user;
    }
}
