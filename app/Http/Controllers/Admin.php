<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Validator;
use Illuminate\Contracts\Encryption\DecryptException;

use App\M_Admin;

use \Firebase\JWT\JWT;

class Admin extends Controller
{
    public function tambahAdmin(Request $request){
        $validator = Validator::make($request->all(),[
            'nama' => 'required',
            'email' => 'required | unique:tbl_user',
            'password' => 'required',
            'token' => 'required'
        ]);
        if($validator->fails()){
            return response()->json([
                'status' => 'Gagal',
                'message' => $validator->messages()
            ]);
        }

        if(M_Admin::create([
            'nama' => $request-> nama,
            'email' => $request-> email,
            'password' => encrypt($request-> password)
        ])){
            return response()->json([
                'status' => 'Berhasil',
                'message' => 'Data Berhasil Disimpan'
            ]);
        }else{
            return response()->json([
                'status' => 'Gagal',
                'message' => 'Data Gagal Disimpan'
            ]);
        }

        $token = $request->token;
        $tokenDb = M_Admin::where('token', $token)->count();
        if($tokenDb > 0){
            $key = env('APP_KEY');
            $decoded = JWT::decode($token, $key, array('HS256'));
            $decoded_array = (array) $decoded;

            if($decoded_array['extime']>time()){
                if(M_Admin::create([
                    'nama' => $request-> nama,
                    'email' => $request-> email,
                    'password' => encrypt($request-> password)
                ])){
                    return response()->json([
                        'status' => 'Berhasil',
                        'message' => 'Data Berhasil Disimpan'
                    ]);
                }else{
                    return response()->json([
                        'status' => 'Gagal',
                        'message' => 'Data Gagal Disimpan'
                    ]);
                }
            }else{
                return response()->json([
                    'status' => 'Gagal',
                    'message' => 'Token Kadaluarsa'
                ]);
            }
        }else{
            return response()->json([
                'status' => 'Gagal',
                'message' => 'Token Tidak Valid'
            ]);
        }
    }

    public function loginAdmin(Request $request){
        $validator = Validator::make($request->all(),[
            'email' => 'required',
            'password' => 'required'
        ]);
        if($validator->fails()){
            return response()->json([
                'status' => 'gagal',
                'message' => $validator->messages()
            ]);
        }

        $cek = M_Admin::where('email', $request->email)->count();
        $admin = M_Admin::where('email', $request->email)->get();

        if($cek>0){
            foreach ($admin as $adm) {
                if($request->password == decrypt($adm->password)){
                    $key = env('APP_KEY');
                    $data = array(
                        'extime' => time()+(60*120),
                        'id_admin' => $adm->id_user
                    );
                    $jwt = JWT::encode($data,$key);

                    M_Admin::where('id_user', $adm->id_user)->update([
                        'token' => $jwt
                    ]);
                    return response()->json([
                        'status' => 'Berhasil',
                        'message' => 'Berhasil Login',
                        'token' => $jwt
                    ]);
                }else{
                    return response()->json([
                        'status' => 'Gagal',
                        'message' => 'Password Salah'
                    ]);
                }
            }
        }else{
            return response()->json([
                'status' => 'Gagal',
                'message' => 'Email Tidak Terdaftar'
            ]);
        }
    }

    public function hapusAdmin(Request $request){
        $validator = Validator::make($request->all(),[
            'id_user' => 'required',
            'token' => 'required'
        ]);
        if($validator->fails()){
            return response()->json([
                'status' => 'Gagal',
                'message' => $validator->messages()
            ]);
        }

        $token = $request->token;
        $tokenDb = M_Admin::where('token', $token)->count();
        if($tokenDb > 0){
            $key = env('APP_KEY');
            $decoded = JWT::decode($token, $key, array('HS256'));
            $decoded_array = (array) $decoded;

            if($decoded_array['extime']>time()){
                if(M_Admin::where('id_user', $request->id_user)->delete()){
                    return response()->json([
                        'status' => 'Berhasil',
                        'message' => 'Data Berhasil Dihapus'
                    ]);
                }else{
                    return response()->json([
                        'status' => 'Gagal',
                        'message' => 'Data Gagal Dihapus'
                    ]);
                }
            }else{
                return response()->json([
                    'status' => 'Gagal',
                    'message' => 'Token Kadaluarsa'
                ]);
            }
        }else{
            return response()->json([
                'status' => 'Gagal',
                'message' => 'Token Tidak Valid'
            ]);
        }
    }

    public function listAdmin(Request $request){
        $validator = Validator::make($request->all(),[
            'token' => 'required'
        ]);
        if($validator->fails()){
            return response()->json([
                'status' => 'Gagal',
                'message' => $validator->messages()
            ]);
        }

        $token = $request->token;
        $tokenDb = M_Admin::where('token', $token)->count();
        if($tokenDb > 0){
            $key = env('APP_KEY');
            $decoded = JWT::decode($token, $key, array('HS256'));
            $decoded_array = (array) $decoded;

            if($decoded_array['extime']>time()){
                $admin = M_Admin::get();
                $data = array();

                foreach($admin as $adm){
                    $data[] = array(
                        'nama' => $adm->nama,
                        'email' => $adm->email,
                        'id_user' => $adm->id_user
                    );
                }
                return response()->json([
                    'status' => 'Berhasil',
                    'message' => 'Data Berhasil Diambil',
                    'data' => $data
                ]);

            }else{
                return response()->json([
                    'status' => 'Gagal',
                    'message' => 'Token Kadaluarsa'
                ]);
            }
        }else{
            return response()->json([
                'status' => 'Gagal',
                'message' => 'Token Tidak Valid'
            ]);
        }
    }
}
