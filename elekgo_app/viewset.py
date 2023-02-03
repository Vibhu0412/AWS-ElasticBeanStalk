from rest_framework.viewsets import ViewSet, ModelViewSet
from rest_framework import status
from rest_framework.response import Response
class CustomViewSet(ModelViewSet):

    def retrieve(self, serializer, *args, **kwargs):

        # print("i am here",self.get_object().status)
        response = {"data":serializer,"status":status.HTTP_200_OK}

        # serializer['status'] = status.HTTP_200_OK
        return Response(response,status=status.HTTP_200_OK)

    def list(self, serializer, *args, **kwargs):
        print("i am heereee",serializer)
        response = {"total_vouchers":self.voucher, "data":serializer,"status":status.HTTP_200_OK}

        # serializer.append({"total_vouchers":self.voucher})
        # serializer.append({"status":status.HTTP_200_OK})
        return Response(response,status=status.HTTP_200_OK)

