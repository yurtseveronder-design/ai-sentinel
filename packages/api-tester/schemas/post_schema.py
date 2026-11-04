from pydantic import BaseModel

class PostSchema(BaseModel):
    userId: int
    id: int
    title: str
    body: str