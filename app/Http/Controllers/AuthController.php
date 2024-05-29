<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Validation\Rules\Password;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' =>[
                'required',
                Password::min(8)
                ->letters()
                ->mixedCase()
                ->numbers()
                ->symbols()
            ]
        ]);

        $user = User::create([
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => Hash::make($validatedData['password']),
        ]);

        // Gere um token para o usuário
    $token = JWTAuth::fromUser($user);

    // Retorne o token e o usuário na resposta
    return response()->json([
        'access_token' => $token,
        'token_type' => 'bearer',
        'user' => $user,
        'expires_in' => JWTAuth::factory()->getTTL() * 60,
    ]);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!$token = Auth::guard('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }
    public function logout(Request $request)
    {
        // Invalida o token
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'Successfully logged out']);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to logout, please try again'], 500);
        }
    }
    /**
     * Get the token array structure.
     *
     * @param string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken(string $token)
    {
      
        $ttl = config('jwt.ttl'); // Tempo de vida do token em minutos

        // Tente obter o usuário autenticado
        $user = Auth::guard('api')->user();

        // Se não houver usuário autenticado, retorne um erro
        if (!$user) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }

       return response()
            ->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'user' => $user,
                'expires_in' => time() + $ttl * 60
            ])
            ->cookie('token', $token, $ttl, '/', null, true, true); // Cookie seguro
    }
}
