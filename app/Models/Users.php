<?php

namespace App\Models;

use CodeIgniter\Model;

class Users extends Model
{
    protected $table            = 'users';
    protected $primaryKey       = 'id';
    protected $useAutoIncrement = true;
    protected $returnType       = 'array';
    protected $useSoftDeletes   = true; // Soft deletes diaktifkan
    protected $protectFields    = true;
    protected $allowedFields    = ['name', 'email', 'password'];

    // Dates
    protected $useTimestamps = true; // Timestamps diaktifkan
    protected $dateFormat    = 'datetime';
    protected $createdField  = 'created_at';
    protected $updatedField  = 'updated_at';
    protected $deletedField  = 'deleted_at';

    // Validation (optional, bisa ditambahkan untuk keamanan)
    protected $validationRules    = [
        'name'     => 'required|min_length[3]|max_length[100]',
        'email'    => 'required|valid_email|is_unique[users.email]',
        'password' => 'required|min_length[6]'
    ];
    protected $validationMessages = [
        'email' => [
            'is_unique' => 'The email address is already taken.'
        ]
    ];
    protected $skipValidation = false;

    // Callbacks (optional, bisa diaktifkan jika perlu)
    protected $allowCallbacks = true;
    protected $beforeInsert   = ['hashPassword'];
    protected $afterInsert    = [];
    protected $beforeUpdate   = ['hashPassword'];
    protected $afterUpdate    = [];
    protected $beforeFind     = [];
    protected $afterFind      = [];
    protected $beforeDelete   = [];
    protected $afterDelete    = [];

    // Hash password sebelum insert/update
    protected function hashPassword(array $data)
    {
        if (isset($data['data']['password'])) {
            $data['data']['password'] = password_hash($data['data']['password'], PASSWORD_DEFAULT);
        }
        return $data;
    }
}
