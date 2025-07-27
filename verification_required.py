from functools import wraps
from flask import request, jsonify
import jwt
from src.models.user import User

def verification_required(f):
    """
    Decorator que verifica se o usuário foi verificado (passou pela verificação de identidade)
    antes de permitir acesso a certas funcionalidades do aplicativo
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar se há token de autorização
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token de autorização necessário'}), 401
        
        try:
            # Extrair e verificar o token
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, 'asdf#FGSgvasgf$5$WGT', algorithms=['HS256'])
            user_id = payload['user_id']
            
            # Buscar o usuário
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'Usuário não encontrado'}), 404
            
            # Verificar se o usuário foi verificado
            if not user.is_verified:
                return jsonify({
                    'error': 'Verificação de identidade necessária',
                    'message': 'Para acessar esta funcionalidade, você precisa completar a verificação de identidade.',
                    'verification_required': True
                }), 403
            
            # Adicionar user_id ao request para uso na função
            request.current_user_id = user_id
            request.current_user = user
            
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        except Exception as e:
            return jsonify({'error': 'Erro na verificação de autenticação', 'details': str(e)}), 500
    
    return decorated_function

def optional_verification_check(f):
    """
    Decorator que verifica se o usuário foi verificado, mas não bloqueia o acesso
    Adiciona informações sobre o status de verificação ao response
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar se há token de autorização
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return f(*args, **kwargs)
        
        try:
            # Extrair e verificar o token
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, 'asdf#FGSgvasgf$5$WGT', algorithms=['HS256'])
            user_id = payload['user_id']
            
            # Buscar o usuário
            user = User.query.get(user_id)
            if user:
                request.current_user_id = user_id
                request.current_user = user
                request.user_verified = user.is_verified
            
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            pass  # Ignorar erros de token para verificação opcional
        
        return f(*args, **kwargs)
    
    return decorated_function

